
#include "dlms-keys.h"

const uint8_t KEY_LEN = 16;
const uint8_t IV_LEN = 12;
const uint8_t AAD_LEN = 17;
const uint8_t TAG_LEN = 12;

uint8_t glo_KEY[KEY_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

uint8_t ded_KEY[KEY_LEN] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

uint8_t ciph_AAD[AAD_LEN] = {
	0x00,	// Placeholder for the Security Control field
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
};

uint8_t client_system_title[8] = {
	0x4d, 0x4d, 0x4d, 0x00, 0x00, 0xbc, 0x61, 0x4e			// DLMS-UA
	// 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48			// Gurux
};
uint8_t server_system_title[8] = {
	// 0x4d, 0x4d, 0x4d, 0x00, 0x00, 0xbc, 0x61, 0x4e			// DLMS-UA
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48			// Gurux
};

void hex_to_uint8(const char *hex_str, uint8_t *buf, int len) {
	for (int i = 0; i < len; i++) {
            sscanf(hex_str + 2 * i, "%2hhx", buf + i);
	}
}

void read_key_from_file(const char *filename, uint8_t *key_buf) {
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Error opening file %s\n", filename);
		exit(1);
	}

	char key[17];
	fgets(key, 17, f);
	hex_to_uint8(key, key_buf, 16);
	fclose(f);
}

void read_client_system_title_from_file(const char *filename, uint8_t *client_system_title_buf) {
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Error opening file %s\n", filename);
		exit(1);
	}

	char client_system_title[17];
	fgets(client_system_title, 17, f);
	hex_to_uint8(client_system_title, client_system_title_buf, 8);
	fclose(f);
}

void read_server_system_title_from_file(const char *filename, uint8_t *server_system_title_buf) {
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Error opening file %s\n", filename);
		exit(1);
	}

	char server_system_title[17];
	fgets(server_system_title, 17, f);
	hex_to_uint8(server_system_title, server_system_title_buf, 8);
	fclose(f);
}

void read_aad_from_file(const char *filename, uint8_t *aad_buf) {
	FILE *f = fopen(filename, "r");
	if (f == NULL) {
		fprintf(stderr, "Error opening file %s\n", filename);
		exit(1);
	}

	char aad[35];
	fgets(aad, 35, f);
	hex_to_uint8(aad, aad_buf, 17);
	fclose(f);
}
