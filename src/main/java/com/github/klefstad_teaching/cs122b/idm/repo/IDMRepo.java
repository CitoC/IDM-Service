package com.github.klefstad_teaching.cs122b.idm.repo;

import com.github.klefstad_teaching.cs122b.idm.repo.entity.type.UserStatus;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class IDMRepo
{
    private final NamedParameterJdbcTemplate template;

    @Autowired
    public IDMRepo(NamedParameterJdbcTemplate template)
    {
        this.template = template;
    }

    // create a user with the email, salt, and hashedPassword. Userstatus is ACTIVE by default
    // salt and password are both encoded to base64. password is also hashed
    public void addUserToDB(String email, String salt, String password) throws DuplicateKeyException {
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
}