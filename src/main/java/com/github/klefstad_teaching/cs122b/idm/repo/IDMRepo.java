package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.User;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.TokenStatus;
import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

import java.sql.Timestamp;
import java.sql.Types;
import java.time.Instant;

@Component
public class IDMRepo
{
    private final NamedParameterJdbcTemplate template;

    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
        this.template = template;
    }

    // create a user with the email, salt, and hashedPassword.
    // UserStatus is ACTIVE by default.
    // salt and password are both encoded to base64. password is also hashed
    public void addUserToDB(String email, String salt, String password)
            throws DuplicateKeyException
    {
        this.template.update(
                "INSERT INTO idm.user (email, user_status_id, salt, hashed_password)" +
                        "VALUES (:email, :userStatusId, :salt, :hashedPassword)",
                new MapSqlParameterSource()
                        .addValue("email", email)
                        .addValue("userStatusId", UserStatus.ACTIVE.id())
                        .addValue("salt", salt)
                        .addValue("hashedPassword", password)
        );
    }

    // select a user with the matching email
    // if such email exists, return exactly ONE object
    // if not, throw an exception
    public User selectAUser(String email, char[] password)
    {
        try {
            User user = this.template.queryForObject(
                    "SELECT id, email, user_status_id, salt, hashed_password " +
                            "FROM idm.user " +
                            "WHERE email = :email",

                    new MapSqlParameterSource()
                            .addValue("email", email, Types.VARCHAR),

                    (rs, rowNum) ->
                            new User()
                                    .setId(rs.getInt("id"))
                                    .setEmail(rs.getString("email"))
                                    .setUserStatus(UserStatus.fromId(rs.getInt("user_status_id")))
                                    .setSalt(rs.getString("salt"))
                                    .setHashedPassword(rs.getString("hashed_password"))
            );
            return user;
        } catch (EmptyResultDataAccessException e) {
            throw new ResultError(IDMResults.USER_NOT_FOUND);
        }
    }

    public void addRefreshTokenToDB(String token, Integer userId, TokenStatus tokenStatus, Instant expireTime, Instant maxLifeTime)
    {
        this.template.update(
                "INSERT INTO idm.refresh_token (token, user_id, token_status_id, expire_time, max_life_time) " +
                        "VALUES (:token, :userId, :tokenStatus, :expireTime, :maxLifeTime)",

                new MapSqlParameterSource()
                        .addValue("token", token)
                        .addValue("userId", userId)
                        .addValue("tokenStatus", tokenStatus.id())
                        .addValue("expireTime", Timestamp.from(expireTime))
                        .addValue("maxLifeTime", Timestamp.from(maxLifeTime))
        );
    }
}