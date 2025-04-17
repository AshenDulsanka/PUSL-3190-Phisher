// email validation using regex
export const validateEmail = (email) => {
    if (typeof email !== 'string' || email.length > 320) return false; // sanity check with size limit
    
    const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return emailRegex.test(email);
}

// password validation - at least 8 chars, 1 number, 1 uppercase, 1 lowercase
export const validatePassword = (password) => {
    if (typeof password !== 'string') return false;
    if (password.length < 8) return false;
    if (!/[0-9]/.test(password)) return false;
    if (!/[a-z]/.test(password)) return false;
    if (!/[A-Z]/.test(password)) return false;
    
    return true;
}