#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <map>

// Function to trim whitespace from the start and end of a string
std::string trim(const std::string& str) {
    const auto strBegin = str.find_first_not_of(" \t");
    if (strBegin == std::string::npos)
        return ""; // no content

    const auto strEnd = str.find_last_not_of(" \t");
    const auto strRange = strEnd - strBegin + 1;

    return str.substr(strBegin, strRange);
}

// Function to read the .env file and store key-value pairs in a map
std::map<std::string, std::string> readEnvFile(const std::string& filePath) {
    std::map<std::string, std::string> envMap;
    std::ifstream file(filePath);

    if (!file.is_open()) {
        std::cerr << "Error: Could not open .env file at " << filePath << std::endl;
        return envMap;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Ignore empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }

        // Split line into key and value
        size_t delimiterPos = line.find('=');
        if (delimiterPos != std::string::npos) {
            std::string key = trim(line.substr(0, delimiterPos));
            std::string value = trim(line.substr(delimiterPos + 1));
            envMap[key] = value;
        }
    }

    file.close();
    return envMap;
}
