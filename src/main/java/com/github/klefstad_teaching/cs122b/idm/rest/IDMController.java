package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.request.AuthRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.LoginRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.RefreshRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.RegisterRequest;
import com.github.klefstad_teaching.cs122b.idm.model.response.AuthResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.LoginResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.RefreshResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.RegisterResponse;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;

@RestController
public class IDMController
{
    private final IDMAuthenticationManager authManager;
    private final IDMJwtManager            jwtManager;
    private final Validate                 validate;


    @Autowired
    public IDMController(IDMAuthenticationManager authManager,
                         IDMJwtManager jwtManager,
                         Validate validate, NamedParameterJdbcTemplate template)
    {
        this.authManager = authManager;
        this.jwtManager = jwtManager;
        this.validate = validate;
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@RequestBody RegisterRequest request) {

        // user with this email already exists - catch in addUserToDB()

        // validate if password does not match length requirements
        // validate if password does not meet character requirement
        validate.validatePassword(request.getPassword());

        // validate if email address has invalid format
        // validate if email address has invalid length
        validate.validateEmail(request.getEmail());

        // no more error (except the email already exists
        // which is handled by the Spring's DuplicateKeyException),
        // go ahead and the user in the database
        authManager.createAndInsertUser(request.getEmail(), request.getPassword());

        // create register response object
        RegisterResponse response = new RegisterResponse()
                .setResult(IDMResults.USER_REGISTERED_SUCCESSFULLY);
        // return the object
        return ResponseEntity
                .status(response.getResult().status())
                .body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) throws JOSEException {
        // validate if password does not match length requirements
        // validate if password does not meet character requirement
        validate.validatePassword(request.getPassword());

        // validate if email address has invalid format
        // validate if email address has invalid length
        validate.validateEmail(request.getEmail());

        // validate if user with email exists
        // validate if the password matches
        // validate if user is locked
        // validate if user is banned
        User user = authManager.selectAndAuthenticateUser(request.getEmail(), request.getPassword());

        // no more error to check beyond this point
        // create an accessToken and a refreshToken
        // in addition, also store the refreshToken into database
        RefreshToken refreshToken = jwtManager.buildRefreshToken(user);
        String accessToken = jwtManager.buildAccessToken(user);
        authManager.insertRefreshToken(refreshToken);

        // create login response object
        LoginResponse response = new LoginResponse()
                .setResult(IDMResults.USER_LOGGED_IN_SUCCESSFULLY)
                .setAccessToken(accessToken)
                .setRefreshToken(refreshToken.getToken());
        // return the object
        return ResponseEntity
                .status(response.getResult().status())
                .body(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<RefreshResponse> refresh(@RequestBody RefreshRequest request) throws JOSEException {
        // validate if refresh token has invalid length
        // needs to have exactly 36 character
        validate.validateRefreshTokenLength(request.getRefreshToken());

        // validate if refresh token has invalid format
        // needs to be UUID formatted string
        validate.validateRefreshTokenFormat(request.getRefreshToken());

        // check if token exists
        // if not, throw
        RefreshToken refreshToken = authManager.verifyRefreshTokenExists(request.getRefreshToken());

        // check if token status is EXPIRED
        // if yes, then throw
        jwtManager.hasExpiredStatus(refreshToken);

        // check if token status is REVOKED
        // if yes, then throw
        jwtManager.hasRevokedStatus(refreshToken);

        // check if current time is after expired time
        // if so, change token status to EXPIRED then throw
        if (Instant.now().isAfter(refreshToken.getExpireTime()) ||
                Instant.now().isAfter(refreshToken.getMaxLifeTime()))
        {
            authManager.expireRefreshToken(refreshToken);
        }

        // update refresh token expire time
        Duration expireDuration = jwtManager.getRefreshTokenExpireDuration();
        authManager.updateRefreshTokenExpireTime(refreshToken, expireDuration);

        // check if the new expire time is after the max expire time
        // if so, change token status to REVOKED, and then return new refreshToken and accessToken
        if (refreshToken.getExpireTime().isAfter(refreshToken.getMaxLifeTime()))
        {
            authManager.revokeRefreshToken(refreshToken);
            User user = authManager.getUserFromRefreshToken(refreshToken);
            RefreshToken newRefreshToken = jwtManager.buildRefreshToken(user);
            String newAccessToken = jwtManager.buildAccessToken(user);
            authManager.insertRefreshToken(newRefreshToken);

            RefreshResponse response = new RefreshResponse()
                    .setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN)
                    .setAccessToken(newAccessToken)
                    .setRefreshToken(newRefreshToken.getToken());
            // return the object
            return ResponseEntity
                    .status(response.getResult().status())
                    .body(response);
        }

        // final condition
        // no more error after this part
        User user = authManager.getUserFromRefreshToken(refreshToken);
        String newAccessToken = jwtManager.buildAccessToken(user);

        RefreshResponse response = new RefreshResponse()
                .setResult(IDMResults.RENEWED_FROM_REFRESH_TOKEN)
                .setAccessToken(newAccessToken)
                .setRefreshToken(refreshToken.getToken());
        // return the object
        return ResponseEntity
                .status(response.getResult().status())
                .body(response);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthResponse> authenticate(@RequestBody AuthRequest request)
            throws BadJOSEException, ParseException, JOSEException
    {
        // verify if token is invalid or expired
        // if yes, then throw exception
        jwtManager.verifyAccessToken(request.getAccessToken());

        // the accessToken is valid
        AuthResponse response = new AuthResponse()
                .setResult(IDMResults.ACCESS_TOKEN_IS_VALID);
        return ResponseEntity
                .status(response.getResult().status())
                .body(response);
    }
}