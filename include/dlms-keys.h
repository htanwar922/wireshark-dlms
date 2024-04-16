#include <stdint.h>
#include <gcrypt.h>

#include "utils/headers.h"

const uint8_t glo_KEY[16] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const uint8_t client_system_title[8] = {
	0x4d, 0x4d, 0x4d, 0x00, 0x00, 0xbc, 0x61, 0x4e			// DLMS-UA
	// 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48			// Gurux
};
const uint8_t server_system_title[8] = {
	// 0x4d, 0x4d, 0x4d, 0x00, 0x00, 0xbc, 0x61, 0x4e			// DLMS-UA
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48			// Gurux
};

uint8_t glo_AAD[] = {
	0x00,	// Placeholder for the Security Control field
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
};

const uint8_t KEY_LEN = 16;
const uint8_t IV_LEN = 12;
const uint8_t AAD_LEN = 17;
const uint8_t TAG_LEN = 12;

class AES
{
protected:
	const gcry_cipher_algos cipher = GCRY_CIPHER_AES128;
	const gcry_cipher_modes mode = GCRY_CIPHER_MODE_GCM;

	const uint8_t * key = NULL, * iv = NULL;
	int key_len = 0, iv_len = 0, tag_len = 0;
public:
	AES(gcry_cipher_algos cipher, gcry_cipher_modes mode, const uint8_t * key, int key_len, const uint8_t * iv, int iv_len, int tag_len = 0)
	: cipher(cipher)
	, mode(mode)
	, key_len(key_len)
	, iv_len(iv_len)
	, tag_len(tag_len)
	{
		this->key = new uint8_t[key_len];
		this->iv = new uint8_t[iv_len];
		if (key)
			memcpy((void *)this->key, (void *)key, key_len);
		if (iv)
			memcpy((void *)this->iv, (void *)iv, iv_len);
	}

	int Encrypt(const uint8_t * plaintext, int len, uint8_t * &ciphertext, uint8_t * tag = NULL, uint8_t * aad = NULL, int aad_len = 0)
	{
		// Encrypt the plaintext
		// Return the ciphertext
		// Return the tag
		// Return the aad
		return -1;
	}

	int Decrypt(const uint8_t * ciphertext, int len, uint8_t * &plaintext, const uint8_t * tag = NULL, const uint8_t * aad = NULL, int aad_len = 0)
	{
		gcry_cipher_hd_t handle;
		gcry_error_t err;

		// Initialize the Libgcrypt library
		if (!gcry_check_version(GCRYPT_VERSION)) {
			g_print("Libgcrypt version mismatch");
		}
		if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
			gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0); // Allocate 16 KiB of secure memory
			gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
		}

		err = gcry_cipher_open(&handle, cipher, mode, 0);
		if (err) {
			g_print("Failed to open cipher context");
		}

		err = gcry_cipher_setkey(handle, key, KEY_LEN);
		if (err) {
			g_print("Failed to set key");
		}

		err = gcry_cipher_setiv(handle, iv, IV_LEN);
		if (err) {
			g_print("Failed to set IV");
		}

		err = gcry_cipher_authenticate(handle, aad, aad_len);
		if (err) {
			g_print("Failed to authenticate AAD");
		}

		err = gcry_cipher_decrypt(handle, plaintext, len, ciphertext, len);
		if (err) {
			g_print("Decryption failed");
		}

		if (tag) {
			err = gcry_cipher_checktag(handle, tag, TAG_LEN);
			if (err) {
				g_print("Failed to check tag");
			}
		}

		gcry_cipher_close(handle);
		return len;
	}

	~AES()
	{
		if (key)
			delete[] key;
		if (iv)
			delete[] iv;
	}
};

class AES_128_GCM : public AES
{
public:
	AES_128_GCM(const uint8_t * key, const uint8_t * iv)
	: AES(GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM, key, KEY_LEN, iv, IV_LEN, TAG_LEN)
	{
	}
};