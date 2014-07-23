#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include "xpwn/libxpwn.h"
#include "xpwn/nor_files.h"
#include "xpwn/img3.h"

#define BUFFERSIZE (1024*1024)

static size_t download_write_callback(void *buffer, size_t size, size_t nmemb, void *userp);

int main(int argc, char* argv[]) {
	char* inData;
	size_t inDataSize;
	init_libxpwn();

	if(argc < 3) {
		printf("usage: %s <infile> <outfile> [-x24k] [-t <template> [-c <certificate>]] [-k <key>] [-iv <key>] [-decrypt]\n", argv[0]);
		return 0;
	}

	AbstractFile* template = NULL;
	AbstractFile* certificate = NULL;
	unsigned int* key = NULL;
	unsigned int* iv = NULL;
	int hasKey = FALSE;
	int hasIV = FALSE;
	int x24k = FALSE;
	int doDecrypt = FALSE;

	int argNo = 3;
	while(argNo < argc) {
		if(strcmp(argv[argNo], "-t") == 0 && (argNo + 1) < argc) {
			template = createAbstractFileFromFile(fopen(argv[argNo + 1], "rb"));
			if(!template) {
				fprintf(stderr, "error: cannot open template\n");
				return 1;
			}
		}

		if(strcmp(argv[argNo], "-decrypt") == 0) {
			doDecrypt = TRUE;
			template = createAbstractFileFromFile(fopen(argv[1], "rb"));
			if(!template) {
				fprintf(stderr, "error: cannot open template\n");
				return 1;
			}
		}

		if(strcmp(argv[argNo], "-c") == 0 && (argNo + 1) < argc) {
			certificate = createAbstractFileFromFile(fopen(argv[argNo + 1], "rb"));
			if(!certificate) {
				fprintf(stderr, "error: cannot open template\n");
				return 1;
			}
		}

		if(strcmp(argv[argNo], "-k") == 0 && (argNo + 1) < argc) {
			size_t bytes;
			hexToInts(argv[argNo + 1], &key, &bytes);
			hasKey = TRUE;
		}

		if(strcmp(argv[argNo], "-iv") == 0 && (argNo + 1) < argc) {
			size_t bytes;
			hexToInts(argv[argNo + 1], &iv, &bytes);
			hasIV = TRUE;
		}

		if(strcmp(argv[argNo], "-x24k") == 0) {
			x24k = TRUE;
		}

		argNo++;
	}

	if (!hasKey || !hasIV) {
		Img3Element* kbag = (Img3Element*) malloc(sizeof(Img3Element));
		kbag = getImg3InfoKbag(createAbstractFileFromFile(fopen(argv[1], "rb")));
		uint8_t* keySeed;
		uint32_t keySeedLen;
		keySeedLen = 16 + (((AppleImg3KBAGHeader*)kbag->data)->key_bits)/8;
		keySeed = (uint8_t*) malloc(keySeedLen);
		memcpy(keySeed, (uint8_t*)((AppleImg3KBAGHeader*)kbag->data) + sizeof(AppleImg3KBAGHeader), keySeedLen);
		int i = 0;
		char outputBuffer[256];
		char curBuffer[256];
		outputBuffer[0] = '\0';
		strcat(outputBuffer, "http://api.ineal.me/xpwnkeys/");
		for(i = 0; i < keySeedLen; i++) {
			sprintf(curBuffer, "%02x", keySeed[i]);
			strcat(outputBuffer, curBuffer);
		}
		free(keySeed);
		free(kbag);

		CURL* curl_handle = curl_easy_init();
		char* response = NULL;
		curl_easy_setopt(curl_handle, CURLOPT_URL, outputBuffer);
		curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, download_write_callback);
		curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);
		curl_easy_perform(curl_handle);
		curl_easy_cleanup(curl_handle);

		char* tempIV = strtok(response, ":");
		char* tempKey = strtok(NULL, ":");

		size_t bytes;
		hexToInts(tempIV, &iv, &bytes);
		hexToInts(tempKey, &key, &bytes);
		hasIV = TRUE;
		hasKey = TRUE;
	}

	AbstractFile* inFile;
	if(doDecrypt) {
		if(hasKey) {
			inFile = openAbstractFile3(createAbstractFileFromFile(fopen(argv[1], "rb")), key, iv, 0);
		} else {
			inFile = openAbstractFile3(createAbstractFileFromFile(fopen(argv[1], "rb")), NULL, NULL, 0);
		}
	} else {
		if(hasKey) {
			inFile = openAbstractFile2(createAbstractFileFromFile(fopen(argv[1], "rb")), key, iv);
		} else {
			inFile = openAbstractFile(createAbstractFileFromFile(fopen(argv[1], "rb")));
		}
	}
	if(!inFile) {
		fprintf(stderr, "error: cannot open infile\n");
		return 2;
	}

	AbstractFile* outFile = createAbstractFileFromFile(fopen(argv[2], "wb"));
	if(!outFile) {
		fprintf(stderr, "error: cannot open outfile\n");
		return 3;
	}


	AbstractFile* newFile;

	if(template) {
		if(hasKey && !doDecrypt) {
			newFile = duplicateAbstractFile2(template, outFile, key, iv, certificate);
		} else {
			newFile = duplicateAbstractFile2(template, outFile, NULL, NULL, certificate);
		}
		if(!newFile) {
			fprintf(stderr, "error: cannot duplicate file from provided template\n");
			return 4;
		}
	} else {
		newFile = outFile;
	}

	if(hasKey && !doDecrypt) {
		if(newFile->type == AbstractFileTypeImg3) {
			AbstractFile2* abstractFile2 = (AbstractFile2*) newFile;
			abstractFile2->setKey(abstractFile2, key, iv);
		}
	}

	if(x24k) {
		if(newFile->type == AbstractFileTypeImg3) {
			exploit24kpwn(newFile);
		}
	}

	inDataSize = (size_t) inFile->getLength(inFile);
	inData = (char*) malloc(inDataSize);
	inFile->read(inFile, inData, inDataSize);
	inFile->close(inFile);

	newFile->write(newFile, inData, inDataSize);
	newFile->close(newFile);

	free(inData);

	if(key)
		free(key);

	if(iv)
		free(iv);

	return 0;
}

static size_t download_write_callback(void *buffer, size_t size, size_t nmemb, void *userp) {
	char **response_ptr =  (char**)userp;
	*response_ptr = strndup(buffer, (size_t)(size *nmemb));
}
