
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdint>
#include <cstring> 
#include <cstddef> 

using namespace std;

#pragma pack(push, 1)
struct BMPFileHeader
{
    uint16_t bfType; // 'BM' = 0x4D42
    uint32_t bfSize;
    uint16_t bfReserved1;
    uint16_t bfReserved2;
    uint32_t bfOffBits;
};
struct BMPInfoHeader
{
    uint32_t biSize; // should be 40
    int32_t biWidth;
    int32_t biHeight;
    uint16_t biPlanes;
    uint16_t biBitCount; // we expect 24
    uint32_t biCompression;
    uint32_t biSizeImage;
    int32_t biXPelsPerMeter;
    int32_t biYPelsPerMeter;
    uint32_t biClrUsed;
    uint32_t biClrImportant;
};
#pragma pack(pop)

// Metadata layout (little endian):
// [uint32_t length][uint8_t cipher_id][uint32_t checksum]
// total metadata bytes = 9

// helper read/write
static inline uint32_t le_to_uint32(const unsigned char *b)
{
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

vector<unsigned char> read_file_bytes(const string &path)
{
    ifstream f(path, ios::binary);
    if (!f)
        throw runtime_error("Cannot open file: " + path);
    f.seekg(0, ios::end);
    size_t n = f.tellg();
    f.seekg(0, ios::beg);
    vector<unsigned char> buf(n);
    f.read((char *)buf.data(), n);
    return buf;
}

void write_file_bytes(const string &path, const vector<unsigned char> &buf)
{
    ofstream f(path, ios::binary);
    if (!f)
        throw runtime_error("Cannot write file: " + path);
    f.write((const char *)buf.data(), buf.size());
}

// BMP loader for 24-bit uncompressed
struct BMPImage
{
    BMPFileHeader fh;
    BMPInfoHeader ih;
    vector<unsigned char> pixels; // BGR, bottom-up rows, with row padding included
    int rowSize;                  // bytes per row including padding
};

BMPImage load_bmp_24(const string &path)
{
    auto data = read_file_bytes(path);
    if (data.size() < sizeof(BMPFileHeader) + sizeof(BMPInfoHeader))
        throw runtime_error("File too small to be BMP");
    BMPImage img;
    memcpy(&img.fh, data.data(), sizeof(BMPFileHeader));
    memcpy(&img.ih, data.data() + sizeof(BMPFileHeader), sizeof(BMPInfoHeader));

    if (img.fh.bfType != 0x4D42)
        throw runtime_error("Not a BMP file (bfType mismatch)");
    if (img.ih.biBitCount != 24)
        throw runtime_error("Only 24-bit BMP supported in this implementation");
    if (img.ih.biCompression != 0)
        throw runtime_error("Compressed BMP not supported");

    int w = img.ih.biWidth;
    int h = abs(img.ih.biHeight);
    int rowSizeUnpadded = w * 3;
    int rowPad = (4 - (rowSizeUnpadded % 4)) % 4;
    img.rowSize = rowSizeUnpadded + rowPad;
    size_t pixelBytes = img.rowSize * h;
    size_t expectedSize = img.fh.bfOffBits + pixelBytes;
    if (data.size() < expectedSize)
        throw runtime_error("BMP file truncated or inconsistent");

    img.pixels.resize(pixelBytes);
    memcpy(img.pixels.data(), data.data() + img.fh.bfOffBits, pixelBytes);
    return img;
}

void write_bmp_24(const string &path, const BMPImage &img)
{
    // rebuild bytes: headers + pixel data
    vector<unsigned char> out;
    out.resize(img.fh.bfOffBits + img.pixels.size());
    memcpy(out.data(), &img.fh, sizeof(BMPFileHeader));
    memcpy(out.data() + sizeof(BMPFileHeader), &img.ih, sizeof(BMPInfoHeader));
    memcpy(out.data() + img.fh.bfOffBits, img.pixels.data(), img.pixels.size());

    // update bfSize directly
    BMPFileHeader *fh_ptr = reinterpret_cast<BMPFileHeader *>(out.data());
    fh_ptr->bfSize = static_cast<uint32_t>(out.size());

    write_file_bytes(path, out);
}

// simple checksum (not cryptographic). Replace with HMAC-SHA256 when available.
uint32_t simple_checksum(const vector<unsigned char> &data)
{
    uint32_t sum = 0x811C9DC5u;
    for (unsigned char b : data)
    {
        sum = (sum * 16777619u) ^ b;
    }
    return sum;
}

// Convert bytes -> bit vector (msb first inside byte)
vector<int> bytes_to_bits(const vector<unsigned char> &bytes)
{
    vector<int> bits;
    bits.reserve(bytes.size() * 8);
    for (unsigned char b : bytes)
    {
        for (int i = 0; i < 8; ++i)
        {
            bits.push_back((b >> i) & 1); // least significant bit first (embedding order)
        }
    }
    return bits;
}
vector<unsigned char> bits_to_bytes(const vector<int> &bits)
{
    if (bits.empty())
        return {};
    size_t nb = (bits.size() + 7) / 8;
    vector<unsigned char> out(nb);
    for (size_t i = 0; i < bits.size(); ++i)
    {
        if (bits[i])
            out[i / 8] |= (1u << (i % 8));
    }
    return out;
}

// LSB embed: overwrite lowest bit of every byte in img.pixels (we'll use entire pixel buffer)
void embed_bits_into_image(BMPImage &img, const vector<int> &bits)
{
    size_t capacity = img.pixels.size(); // 1 bit per byte
    if (bits.size() > capacity)
        throw runtime_error("Not enough capacity to embed message");
    for (size_t i = 0; i < bits.size(); ++i)
    {
        img.pixels[i] = (img.pixels[i] & 0xFE) | (unsigned char)(bits[i]);
    }
}

// LSB extract
vector<int> extract_bits_from_image(const BMPImage &img, size_t nbits)
{
    if (nbits > img.pixels.size())
        throw runtime_error("Requesting more bits than available");
    vector<int> bits(nbits);
    for (size_t i = 0; i < nbits; ++i)
        bits[i] = img.pixels[i] & 1;
    return bits;
}

// Ciphers
enum CipherId : uint8_t
{
    CIPHER_NONE = 0,
    CIPHER_CAESAR = 1,
    CIPHER_VIGENERE = 2
};

// Caesar: add shift modulo 256 to each byte
vector<unsigned char> caesar_encrypt_bytes(const vector<unsigned char> &plain, uint8_t shift)
{
    vector<unsigned char> out(plain.size());
    for (size_t i = 0; i < plain.size(); ++i)
        out[i] = (unsigned char)((plain[i] + shift) & 0xFF);
    return out;
}
vector<unsigned char> caesar_decrypt_bytes(const vector<unsigned char> &cipher, uint8_t shift)
{
    vector<unsigned char> out(cipher.size());
    for (size_t i = 0; i < cipher.size(); ++i)
        out[i] = (unsigned char)((cipher[i] - shift) & 0xFF);
    return out;
}

// Vigenere-style over bytes: add key bytes (mod 256)
vector<unsigned char> vigenere_encrypt_bytes(const vector<unsigned char> &plain, const vector<unsigned char> &key)
{
    if (key.empty())
        throw runtime_error("Vigenere key empty");
    vector<unsigned char> out(plain.size());
    for (size_t i = 0; i < plain.size(); ++i)
        out[i] = (unsigned char)((plain[i] + key[i % key.size()]) & 0xFF);
    return out;
}
vector<unsigned char> vigenere_decrypt_bytes(const vector<unsigned char> &cipher, const vector<unsigned char> &key)
{
    if (key.empty())
        throw runtime_error("Vigenere key empty");
    vector<unsigned char> out(cipher.size());
    for (size_t i = 0; i < cipher.size(); ++i)
        out[i] = (unsigned char)((cipher[i] - key[i % key.size()]) & 0xFF);
    return out;
}

// CLI helpers
void usage()
{
    cout << "Usage:\n";
    cout << "  Embed: stego embed <cover.bmp> <out.bmp> <message.txt> <cipher> <key>\n";
    cout << "         cipher: caesar,<shift>   OR  vigenere,<keystring>\n";
    cout << "  Extract: stego extract <stego.bmp> <out_message.txt> <key>\n";
    cout << "Notes: Implementation supports 24-bit uncompressed BMP only.\n";
}

// Pack metadata + encrypted message into bytes vector
vector<unsigned char> pack_payload(CipherId cid, const vector<unsigned char> &enc_msg)
{
    vector<unsigned char> payload;
    uint32_t msglen = (uint32_t)enc_msg.size();
    // length (4)
    payload.push_back((unsigned char)(msglen & 0xFF));
    payload.push_back((unsigned char)((msglen >> 8) & 0xFF));
    payload.push_back((unsigned char)((msglen >> 16) & 0xFF));
    payload.push_back((unsigned char)((msglen >> 24) & 0xFF));
    // cipher id (1)
    payload.push_back((unsigned char)cid);
    // checksum (4) - compute over enc_msg
    uint32_t cs = simple_checksum(enc_msg);
    payload.push_back((unsigned char)(cs & 0xFF));
    payload.push_back((unsigned char)((cs >> 8) & 0xFF));
    payload.push_back((unsigned char)((cs >> 16) & 0xFF));
    payload.push_back((unsigned char)((cs >> 24) & 0xFF));
    // message bytes
    payload.insert(payload.end(), enc_msg.begin(), enc_msg.end());
    return payload;
}

// Unpack metadata from raw bytes (must be at least 9 bytes)
struct PayloadMeta
{
    uint32_t length;
    CipherId cid;
    uint32_t checksum;
};
PayloadMeta unpack_meta(const vector<unsigned char> &payload)
{
    if (payload.size() < 9)
        throw runtime_error("Payload too small for metadata");
    uint32_t len = (uint32_t)payload[0] | ((uint32_t)payload[1] << 8) | ((uint32_t)payload[2] << 16) | ((uint32_t)payload[3] << 24);
    CipherId cid = (CipherId)payload[4];
    uint32_t cs = (uint32_t)payload[5] | ((uint32_t)payload[6] << 8) | ((uint32_t)payload[7] << 16) | ((uint32_t)payload[8] << 24);
    return {len, cid, cs};
}

int main(int argc, char **argv)
{
    try
    {
        if (argc < 2)
        {
            usage();
            return 1;
        }
        string mode = argv[1];
        if (mode == string("embed"))
        {
            if (argc < 7)
            {
                usage();
                return 1;
            }
            string cover = argv[2];
            string outbmp = argv[3];
            string msgfile = argv[4];
            string cipherArg = argv[5]; // "caesar,5" or "vigenere,mykey"
            string keyArg = argv[6];

            BMPImage img = load_bmp_24(cover);
            // load message
            auto mb = read_file_bytes(msgfile);
            // choose cipher
            CipherId cid = CIPHER_NONE;
            vector<unsigned char> enc;
            if (cipherArg.rfind("caesar", 0) == 0)
            {
                cid = CIPHER_CAESAR;
                // parse shift
                int shift = 0;
                size_t comma = cipherArg.find(',');
                if (comma != string::npos)
                    shift = stoi(cipherArg.substr(comma + 1));
                uint8_t sbyte = (uint8_t)(shift & 0xFF);
                enc = caesar_encrypt_bytes(mb, sbyte);
            }
            else if (cipherArg.rfind("vigenere", 0) == 0)
            {
                cid = CIPHER_VIGENERE;
                // keyArg used as key bytes
                vector<unsigned char> keyBytes(keyArg.begin(), keyArg.end());
                enc = vigenere_encrypt_bytes(mb, keyBytes);
            }
            else
            {
                throw runtime_error("Unknown cipher argument. Use 'caesar,<shift>' or 'vigenere,<ignored>' and provide key.");
            }

            // build payload
            auto payload = pack_payload(cid, enc);
            auto bits = bytes_to_bits(payload);
            size_t capacity_bits = img.pixels.size(); // 1 bit per byte
            if (bits.size() > capacity_bits)
                throw runtime_error("Cover image capacity insufficient. Need " + to_string(bits.size()) + " bits, have " + to_string(capacity_bits));
            embed_bits_into_image(img, bits);
            write_bmp_24(outbmp, img);
            cout << "Embed OK. Message bytes: " << mb.size() << ", embedded bytes (with meta): " << payload.size() << "\n";
            return 0;
        }
        else if (mode == string("extract"))
        {
            if (argc < 5)
            {
                usage();
                return 1;
            }
            string stego = argv[2];
            string outmsg = argv[3];
            string keyArg = argv[4]; // key for decryption (for caesar: pass shift as number; for vigenere: key string)
            BMPImage img = load_bmp_24(stego);

            // first extract metadata bytes (9 bytes -> 72 bits)
            auto metaBits = extract_bits_from_image(img, 9 * 8);
            auto metaBytes = bits_to_bytes(metaBits);
            auto meta = unpack_meta(metaBytes);
            // now extract message bytes:
            size_t totalBits = (size_t)((9 + meta.length) * 8);
            auto allBits = extract_bits_from_image(img, totalBits);
            auto allBytes = bits_to_bytes(allBits);
            // message begins at offset 9
            vector<unsigned char> encMsg;
            encMsg.insert(encMsg.end(), allBytes.begin() + 9, allBytes.begin() + 9 + meta.length);
            // verify checksum
            uint32_t cs = simple_checksum(encMsg);
            if (cs != meta.checksum)
            {
                cerr << "Warning: checksum mismatch. Possible wrong key or corrupted image.\n";
            }
            // decrypt depending on meta.cid
            vector<unsigned char> plain;
            if (meta.cid == CIPHER_CAESAR)
            {
                int shift = stoi(keyArg);
                plain = caesar_decrypt_bytes(encMsg, (uint8_t)shift);
            }
            else if (meta.cid == CIPHER_VIGENERE)
            {
                vector<unsigned char> keyBytes(keyArg.begin(), keyArg.end());
                plain = vigenere_decrypt_bytes(encMsg, keyBytes);
            }
            else if (meta.cid == CIPHER_NONE)
            {
                plain = encMsg;
            }
            else
            {
                throw runtime_error("Unknown cipher id in payload");
            }
            write_file_bytes(outmsg, plain);
            cout << "Extract OK. Output written to " << outmsg << "\n";
            return 0;
        }
        else
        {
            usage();
            return 1;
        }
    }
    catch (exception &e)
    {
        cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}
