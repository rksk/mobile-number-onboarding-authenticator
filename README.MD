# Custom authenticator for phone number onboarding

This component has been tested with WSO2 IS version 5.10.0 and following are the steps to deploy the component in v5.10.0.

### Steps to deploy
- Build the component by running "mvn clean install"
- Copy following jar file which can be found in target directory into <IS_HOME>/repository/components/dropins/
  org.wso2.sample.authenticator.mobile.onboarding-1.0.0.jar
- Configure the customer authenticator by adding following in deployment.toml. You may adjust the values appropriately.
    ```
  [authentication.authenticator.mobile_number_onboarding]
  name = "MobileNumberOnboarding"
  enable = true
  
  [authentication.authenticator.mobile_number_onboarding.parameters]
  SMSOTPAuthenticationEndpointURL = "/smsotpauthenticationendpoint/smsotp-mobile-number-onboarding.jsp"
  SMSOTPAuthenticationEndpointErrorPage = "/smsotpauthenticationendpoint/smsotpError.jsp"
  MobileNumberRegPage = "/smsotpauthenticationendpoint/mobile-number-onboarding.jsp"
  RetryEnable = true
  ResendEnable = true
  TokenExpiryTime = 300
  EnableAccountLockingForFailedAttempts = true
  showAuthFailureReason = true
  usecase = "local"
  secondaryUserstore = "primary"

    ```

- Restart the Identity Server
- Copy the two files in smsotpauthenticationendpoint to <IS_HOME>/repository/deployment/server/webapps/smsotpauthenticationendpoint directory.
- Create an identity provider using the Mobile Number Onboarding authenticator and configure its properties in the same way SMS OTP identity provider was configured.
- Use the above created identity provider in the authentication flow after the user completes the first authentication step using basic auth.
