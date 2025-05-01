package com.example.demo.services;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class CustomStringSetDeserializer extends JsonDeserializer<Set<String>> {
    @Override
    public Set<String> deserialize(JsonParser p, DeserializationContext context)
            throws IOException {
        String value = p.getValueAsString();
        Set<String> result = new HashSet<>();
        if (value != null) {
            result.add(value);
        }
        return result;
    }
}
