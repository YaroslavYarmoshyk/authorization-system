package com.auth.authorizationserver.error;

public class FederatedProvisioningException extends RuntimeException {

    public FederatedProvisioningException(String message) {
        super(message);
    }
}
