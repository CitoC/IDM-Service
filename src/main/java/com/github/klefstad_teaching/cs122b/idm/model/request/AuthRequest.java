package com.github.klefstad_teaching.cs122b.idm.model.request;

public class AuthRequest {
    private String accessToken;

    public String getAccessToken() {
        return accessToken;
    }

    public AuthRequest setAccessToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }
}
