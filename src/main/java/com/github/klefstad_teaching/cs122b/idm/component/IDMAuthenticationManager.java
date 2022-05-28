package com.github.klefstad_teaching.cs122b.idm.component;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.IDMRepo;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.RefreshToken;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.Role;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.Base64;

@Component
public class IDMAuthenticationManager
{
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final String       HASH_FUNCTION = "PBKDF2WithHmacSHA512";

    private static final int ITERATIONS     = 10000;
    private static final int KEY_BIT_LENGTH = 512;

    private static final int SALT_BYTE_LENGTH = 4;

    public final IDMRepo repo;

    @Autowired
    public IDMAuthenticationManager(IDMRepo repo)
    {
        this.repo = repo;
    }

    private static byte[] hashPassword(final char[] password, String salt)
    {
        return hashPassword(password, Base64.getDecoder().decode(salt));
    }

    private static byte[] hashPassword(final char[] password, final byte[] salt)
    {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(HASH_FUNCTION);

            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_BIT_LENGTH);

            SecretKey key = skf.generateSecret(spec);

            return key.getEncoded();

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] genSalt()
    {
        byte[] salt = new byte[SALT_BYTE_LENGTH];
        SECURE_RANDOM.nextBytes(salt);
        return salt;
    }

    // used for login
    public User selectAndAuthenticateUser(String email, char[] password)
    {
        // either will return exactly one user or user not found exception will occur and end
        User user = repo.selectAUser(email, password);

        // check if password matches
        byte[] hashedPassword = hashPassword(password, user.getSalt());
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(hashedPassword);

        if (!base64EncodedHashedPassword.equals(user.getHashedPassword()))
            throw new ResultError(IDMResults.INVALID_CREDENTIALS);

        // check if user locked or banned
        if (user.getUserStatus() == UserStatus.LOCKED)
            throw new ResultError(IDMResults.USER_IS_LOCKED);
        if (user.getUserStatus() == UserStatus.BANNED)
            throw new ResultError(IDMResults.USER_IS_BANNED);

        return user;
    }

    // used for register
    public void createAndInsertUser(String email, char[] password)
    {
        // generate salt and hash the password
        byte[] salt = genSalt();
        byte[] hashedPassword = hashPassword(password,salt);

        // turn the salt and hashed password into base64 string
        String base64EncodedSalt = Base64.getEncoder().encodeToString(salt);
        String base64EncodedHashedPassword = Base64.getEncoder().encodeToString(hashedPassword);

        // add to the database
        try {
            repo.addUserToDB(email, base64EncodedSalt, base64EncodedHashedPassword);
        } catch (DuplicateKeyException e) {
            throw new ResultError(IDMResults.USER_ALREADY_EXISTS);
        }
    }

    public void insertRefreshToken(RefreshToken refreshToken)
    {
        String token = refreshToken.getToken();
        Integer userId = refreshToken.getUserId();
        TokenStatus tokenStatus = refreshToken.getTokenStatus();
        Instant expireTime = refreshToken.getExpireTime();
        Instant maxLifeTime = refreshToken.getMaxLifeTime();
        repo.addRefreshTokenToDB(token, userId, tokenStatus, expireTime, maxLifeTime);
    }

    public RefreshToken verifyRefreshToken(String token)
    {
        // TODO: go into repo and find the refresh token
        return null;
    }

    public void updateRefreshTokenExpireTime(RefreshToken token)
    {
        // TODO: go into repo to update expire time of refresh token
    }

    public void expireRefreshToken(RefreshToken token)
    {
        // TODO: go into repo and
    }

    public void revokeRefreshToken(RefreshToken token)
    {
        // TODO: mark old token as revoked?
    }

    public User getUserFromRefreshToken(RefreshToken refreshToken)
    {
        return null;
    }
}
