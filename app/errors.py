class ErrorCodes:
    MISSING_FIELDS = "missing_fields"
    INVALID_EMAIL = "invalid_email"
    INVALID_MOBILE = "invalid_mobile"
    INVALID_PASSWORD = "invalid_password"
    INVALID_NAME = "invalid_name"
    EMAIL_ALREADY_EXISTS = "email_already_exists"
    MOBILE_ALREADY_EXISTS = "mobile_already_exists"
    USER_NOT_FOUND = "user_not_found"
    INVALID_CREDENTIALS = "invalid_credentials"
    ACCOUNT_INACTIVE = "account_inactive"
    INVALID_OTP = "invalid_otp"
    OTP_ATTEMPTS_EXCEEDED = "otp_attempts_exceeded"
    UNEXPECTED_ERROR = "unexpected_error"


ERROR_MESSAGES = {
    ErrorCodes.MISSING_FIELDS: "Missing required fields.",
    ErrorCodes.INVALID_EMAIL: "Invalid email format.",
    ErrorCodes.INVALID_MOBILE: "Invalid mobile number format.",
    ErrorCodes.INVALID_PASSWORD: "Password must be at least 8 characters long and include uppercase letters, numbers, and special characters.",
    ErrorCodes.INVALID_NAME: "Name must contain only Persian or English letters.",
    ErrorCodes.EMAIL_ALREADY_EXISTS: "Email already exists.",
    ErrorCodes.MOBILE_ALREADY_EXISTS: "Mobile number already exists.",
    ErrorCodes.USER_NOT_FOUND: "User not found.",
    ErrorCodes.INVALID_CREDENTIALS: "Invalid email or password.",
    ErrorCodes.ACCOUNT_INACTIVE: "Account is inactive.",
    ErrorCodes.INVALID_OTP: "Invalid OTP. Please try again.",
    ErrorCodes.OTP_ATTEMPTS_EXCEEDED: "Too many incorrect attempts. User has been disabled.",
    ErrorCodes.UNEXPECTED_ERROR: "An unexpected error occurred.",
}
