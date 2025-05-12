package com.yevsieiev.authstarter.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Base64;

public class CipheringKeyProvider {
    private final String keyPath;

    public CipheringKeyProvider(String keyPath) {
        this.keyPath = keyPath;
    }

    public byte[] getSymmetricKey() throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(Path.of(keyPath).toFile());

        return Base64.getDecoder().decode(
                rootNode.get("key")
                        .get(0)
                        .get("keyData")
                        .get("value")
                        .asText()
        );
    }
}
