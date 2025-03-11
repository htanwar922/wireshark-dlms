#pragma once

#include <stdint.h>
#include <gcrypt.h>

#include "utils/headers.h"

extern const uint8_t KEY_LEN;
extern const uint8_t IV_LEN;
extern const uint8_t AAD_LEN;
extern const uint8_t TAG_LEN;

extern uint8_t glo_KEY[];
extern uint8_t ded_KEY[];
extern uint8_t ciph_AAD[];
extern uint8_t client_system_title[];
extern uint8_t server_system_title[];

void hex_to_uint8(const char *hex_str, uint8_t *buf, int len);

void read_key_from_file(const char *filename, uint8_t *key_buf);
void read_client_system_title_from_file(const char *filename, uint8_t *client_system_title_buf);
void read_server_system_title_from_file(const char *filename, uint8_t *server_system_title_buf);
void read_aad_from_file(const char *filename, uint8_t *aad_buf);

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
