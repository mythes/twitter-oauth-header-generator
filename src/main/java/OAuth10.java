import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.util.*;

import org.apache.commons.codec.binary.Base64;

class OAuth10 {

    private String consumer_key;
    private String consumer_secret_key;
    private String access_token;
    private String access_token_sicret;

    public OAuth10(
            String consumer_key,
            String consumer_secret_key,
            String access_token,
            String access_token_sicret

    ) {
        this.consumer_key = consumer_key;
        this.consumer_secret_key = consumer_secret_key;
        this.access_token = access_token;
        this.access_token_sicret = access_token_sicret;

    }


    private SecureRandom secureRandom = new SecureRandom();

    private long generateTimestamp() {
        return System.currentTimeMillis() / 1000;
    }

    private String generateNonce() {
        byte[] r = new byte[32];
        secureRandom.nextBytes(r);
        return Base64
                .encodeBase64String(r)
                .replaceAll("[^A-Za-z0-9]", "");

    }


    String getAuthorizedHeader(String method, String URI, Map<String, String> params) throws UnsupportedEncodingException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        Map<String, String> headers = new LinkedHashMap<>();

        headers.put("oauth_consumer_key", consumer_key);
        headers.put("oauth_nonce", generateNonce());
        headers.put("oauth_signature", "");
        headers.put("oauth_signature_method", "HMAC-SHA1");
        headers.put("oauth_timestamp", String.valueOf(generateTimestamp()));
        headers.put("oauth_token", access_token);
        headers.put("oauth_version", "1.0");

        headers.replace("oauth_signature", getSignature(method, URI, headers, params));

        StringBuilder outputHeader = new StringBuilder("OAuth ");

//        for (Map.Entry s : headers.entrySet()) {
//            System.out.println(s.getKey() + "=" + s.getValue());
//        }

        for (Map.Entry s : headers.entrySet()) {
            outputHeader
                    .append(percentEncode((String) s.getKey()))
                    .append("=")
                    .append("\"")
                    .append(percentEncode((String) s.getValue()))
                    .append("\"")
                    .append(", ");
        }
        outputHeader.deleteCharAt(outputHeader.lastIndexOf(", "));

        System.out.println("Signature base string :" + outputHeader);
        return outputHeader.toString();
    }

    private String getSignature(String method,
                                String URI,
                                Map<String, String> headers,
                                Map<String, String> params) throws UnsupportedEncodingException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        Map<String, String> transitHeaders = new LinkedHashMap<>(headers);
        transitHeaders.remove("oauth_signature");

        byte[] hmacSha1 = HmacSha1Signature
                .calculateRFC2104HMAC(getSignatureBaseString(method, URI, transitHeaders, params), getSigningKey());

        String oauth10Signature = Base64.encodeBase64String(hmacSha1);

        System.out.println("oauth10Signature is : " + oauth10Signature);

        return oauth10Signature;

    }

    private String getSigningKey() throws UnsupportedEncodingException {
        String output = percentEncode(consumer_secret_key) +
                "&" +
                percentEncode(access_token_sicret);
        return output;
    }

    private String percentEncode(String input) throws UnsupportedEncodingException {
        return URLEncoder.encode(input, "UTF-8");
    }

    private String getSignatureBaseString(String method,
                                          String URI,
                                          Map<String, String> headers,
                                          Map<String, String> params) throws UnsupportedEncodingException {

        StringBuilder sb = new StringBuilder();
        sb
                .append(method.toUpperCase())
                .append("&")
                .append(percentEncode(URI))
                .append("&")
                .append(percentEncode(getParametrString(headers, params)));

        System.out.println("Signature base string: " + sb.toString());
        return sb.toString();
    }

    private String getParametrString(Map<String, String> headers,
                                     Map<String, String> params) throws UnsupportedEncodingException {
        SortedMap<String, String> out = new TreeMap<>();

        out.putAll(percentEncode(headers));

        if (params != null) {
            out.putAll(percentEncode(params));
        }

        StringBuilder sb = new StringBuilder();

        List<String> keys = new ArrayList<>(out.keySet());
        for (String key : keys) {
            sb.append(key)
                    .append("=")
                    .append(out.get(key))
                    .append("&");
        }
        sb.deleteCharAt(sb.lastIndexOf("&"));

        String parameterString = sb.toString();

        System.out.println("Parameter string: " + parameterString);

        return parameterString;
    }


    private Map<String,String> percentEncode(Map<String, String> map) {
        Map <String, String> out= new HashMap<>();

        map.forEach((a, b) -> {
            try {
                out.put(percentEncode(a),percentEncode(b));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        });

        return out;
    }

}
