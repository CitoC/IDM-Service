package com.github.klefstad_teaching.cs122b.idm.util;

import com.github.klefstad_teaching.cs122b.core.error.ResultError;
import com.github.klefstad_teaching.cs122b.core.result.IDMResults;
import org.springframework.stereotype.Component;
import java.util.regex.Pattern;

@Component
public final class Validate
{
    public void validatePassword(char[] password)
    {
        // check password length
        if (password.length < 10 || password.length > 20)
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_LENGTH_REQUIREMENTS);

        // check character requirement
        Boolean hasUpper = false;
        Boolean hasLower = false;
        Boolean hasNumeric = false;

        for (char c: password)
        {
            if (!hasUpper && Character.isUpperCase(c))
                hasUpper = true;
            if (!hasLower && Character.isLowerCase(c))
                hasLower = true;
            if (!hasNumeric && Character.isDigit(c))
                hasNumeric = true;
        }

        if (!hasUpper || !hasLower || !hasNumeric)
            throw new ResultError(IDMResults.PASSWORD_DOES_NOT_MEET_CHARACTER_REQUIREMENT);
    }

    public void validateEmail(String email)
    {
        // check format
        String regexPattern = "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@"
                + "[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$";

        Boolean isValid = Pattern.compile(regexPattern).matcher(email).matches();
        if (!isValid)
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_FORMAT);

        // check length
        if (email.length() < 6 || email.length() > 32)
            throw new ResultError(IDMResults.EMAIL_ADDRESS_HAS_INVALID_LENGTH);
    }

}
