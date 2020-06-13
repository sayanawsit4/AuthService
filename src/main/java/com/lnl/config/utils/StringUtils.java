package com.lnl.config.utils;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.security.crypto.bcrypt.BCrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class StringUtils {

    private static String apiRegex = "^((?!v2).)*$";

    public static Boolean checkpassword(String plain, String hashed) {
        return BCrypt.checkpw(plain, hashed);
    }

    public static Boolean apiVersionCheck(String url) {
        //make pattern static
        Pattern pattern = Pattern.compile(apiRegex);
        return pattern.matcher(url).matches();
    }

    public static String getHmacKeys(String apiName, String time) {
        String hash = null;
        try {
            String secret = "aokishuzo";
            String message = time + "|" + apiName;
            Mac sha256HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            sha256HMAC.init(secretKey);
            hash = Base64.encodeBase64String(sha256HMAC.doFinal(message.getBytes()));

        } catch (Exception e) {
           log.debug("Error");
        }
        return hash;
    }

    public static String sliceError(String requestUrl) {
        String errorRemoved = Arrays.stream(requestUrl.split("&"))
                .filter(s -> !s.contains("error"))
                .collect(Collectors.joining("&"));
        return errorRemoved.isEmpty() ? "" : "&" + errorRemoved;
    }

}