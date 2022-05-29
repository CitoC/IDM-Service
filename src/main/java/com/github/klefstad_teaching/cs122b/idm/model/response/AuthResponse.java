package com.github.klefstad_teaching.cs122b.idm.model.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.github.klefstad_teaching.cs122b.core.result.Result;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {
    private Result result;

    public Result getResult() {
        return result;
    }

    public AuthResponse setResult(Result result) {
        this.result = result;
        return this;
    }
}
