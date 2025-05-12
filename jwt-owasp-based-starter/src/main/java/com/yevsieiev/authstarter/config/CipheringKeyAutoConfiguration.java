package com.yevsieiev.authstarter.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yevsieiev.authstarter.service.CipheringKeyProvider;
import lombok.RequiredArgsConstructor;
import lombok.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Configuration
@EnableConfigurationProperties(ValidationProperties.class)
@RequiredArgsConstructor
public class CipheringKeyAutoConfiguration {
   private final ValidationProperties validationProperties;


    @Bean
    @ConditionalOnMissingBean
    public CipheringKeyProvider cipheringKeyProvider() throws IOException {
        Path keyPath = Paths.get("key-ciphering.json");

        if (!Files.exists(keyPath)) {
            if (validationProperties.getSymmetricKey() == null || validationProperties.getSymmetricKey().isEmpty()) {
                throw new IllegalStateException("Ciphering key value must be provided in application.properties");
            }

            // Создаем JSON структуру
            ObjectNode rootNode = JsonNodeFactory.instance.objectNode();
            rootNode.put("primaryKeyId", 2120840673);

            ArrayNode keyArray = JsonNodeFactory.instance.arrayNode();
            ObjectNode keyNode = JsonNodeFactory.instance.objectNode();

            ObjectNode keyDataNode = JsonNodeFactory.instance.objectNode();
            keyDataNode.put("typeUrl", "type.googleapis.com/google.crypto.tink.AesGcmKey");
            keyDataNode.put("keyMaterialType", "SYMMETRIC");
            keyDataNode.put("value", validationProperties.getSymmetricKey());

            keyNode.set("keyData", keyDataNode);
            keyNode.put("outputPrefixType", "TINK");
            keyNode.put("keyId", 2120840673);
            keyNode.put("status", "ENABLED");

            keyArray.add(keyNode);
            rootNode.set("key", keyArray);

            // Записываем в файл
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(keyPath.toFile(), rootNode);
        }

        return new CipheringKeyProvider(keyPath.toString());
    }
}
