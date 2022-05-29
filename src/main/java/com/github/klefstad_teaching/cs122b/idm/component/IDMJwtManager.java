package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.core.security.JWTManager;
import com.github.klefstad_teaching.cs122b.idm.config.IDMServiceConfig;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.JWSHeader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class IDMJwtManager
{
    private final JWTManager jwtManager;

    @Autowired
    public IDMJwtManager(IDMServiceConfig serviceConfig)
    {
        this.jwtManager =
            new JWTManager.Builder()
                .keyFileName(serviceConfig.keyFileName())
                .accessTokenExpire(serviceConfig.accessTokenExpire())
                .maxRefreshTokenLifeTime(serviceConfig.maxRefreshTokenLifeTime())
                .refreshTokenExpire(serviceConfig.refreshTokenExpire())
                .build();
    }

    public String buildAccessToken(User user)
            throws JOSEException
    {
        SignedJWT signedJWT = buildAndSignJWT(user);
        // serialized the jwt in base 64
        // this is the access token
        String serializedJWT = signedJWT.serialize();

        return serializedJWT;
    }

    private SignedJWT buildAndSignJWT(User user)
        throws JOSEException
    {
        // build jwt (java web token) claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(user.getEmail())
                .expirationTime(
                        Date.from(
                            Instant.now().plus(this.jwtManager.getAccessTokenExpire())))
                .claim(JWTManager.CLAIM_ID, user.getId())
                .claim(JWTManager.CLAIM_ROLES, user.getRoles())
                .issueTime(Date.from(Instant.now()))
                .build();

        // build jws (java web signature) header
        JWSHeader header = new JWSHeader.Builder(JWTManager.JWS_ALGORITHM)
                .keyID(jwtManager.getEcKey().getKeyID())
                .type(JWTManager.JWS_TYPE)
                .build();

        // create JWT and then sign it
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        signedJWT.sign(jwtManager.getSigner());

        return signedJWT;
    }

    public RefreshToken buildRefreshToken(User user)
    {
        RefreshToken refreshToken = new RefreshToken()
                .setToken(generateUUID().toString())
                .setUserId(user.getId())
                .setTokenStatus(TokenStatus.ACTIVE)
                .setExpireTime(Instant.now().plus(jwtManager.getRefreshTokenExpire()))
                .setMaxLifeTime(Instant.now().plus(jwtManager.getMaxRefreshTokenLifeTime()));

        return refreshToken;
    }

    private UUID generateUUID()
    {
        return UUID.randomUUID();
    }

    public void hasExpiredStatus(RefreshToken refreshToken)
    {
        // check if token status is expired
        if (refreshToken.getTokenStatus() == TokenStatus.EXPIRED)
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_EXPIRED);


    }

    public void hasRevokedStatus(RefreshToken refreshToken)
    {
        // check if token status if revoked
        if (refreshToken.getTokenStatus() == TokenStatus.REVOKED)
            throw new ResultError(IDMResults.REFRESH_TOKEN_IS_REVOKED);
    }

    public boolean needsRefresh(RefreshToken refreshToken)
    {
        return false;
    }

    public void updateRefreshTokenExpireTime(RefreshToken refreshToken)
    {

    }

    public Duration getRefreshTokenExpireDuration()
    {
        return this.jwtManager.getRefreshTokenExpire();
    }

    private void verifyJWT(SignedJWT jwt)
            throws JOSEException, BadJOSEException
    {

    }

    public void verifyAccessToken(String jws)
    {

    }
}
