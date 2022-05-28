package com.github.klefstad_teaching.cs122b.idm.rest;

import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.component.IDMAuthenticationManager;
import com.github.klefstad_teaching.cs122b.idm.component.IDMJwtManager;
import com.github.klefstad_teaching.cs122b.idm.model.request.LoginRequest;
import com.github.klefstad_teaching.cs122b.idm.model.request.RegisterRequest;
import com.github.klefstad_teaching.cs122b.idm.model.response.LoginResponse;
import com.github.klefstad_teaching.cs122b.idm.model.response.RegisterResponse;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import com.github.klefstad_teaching.cs122b.idm.util.Validate;
import com.nimbusds.jose.JOSEException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

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


}