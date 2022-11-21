# Ideas
[Idea]
* Implement Cache of User Requests for faster loading.


[Idea]
 
* Store error messages for each operation in a json file.

* Build a User Interface for the API used to manage the state of the API

* One Feature of this Interface is to manage the values of each expected response `message` and `status code` for convince of updating response messages and status codes. Include a message and status code for each expected state in which a response is created.



# Tasks:


[BlogAPI]
[NewFeatures]

* Use Twilio and SendGrid API's to send and confirm email verification services.

    [Register]
    * * Do Nothing About Email Verification 
        Upon successful registration set the `user` field `email_verifed` to `false`

    [SendEmailVerification]
    * * Send Email Verification w/ Twilio / SendGrid
        * Send verification email to an existing user if the `user` field `email_verifed` is `false`

    [ConfirmEmailVerfication]
    * * Confirm the Twilio / SendGrid Verification
        * Provided the verification value sent to the email is valid, set the `user` field `email_verified` to `true` 




[BlogWebApp]

* 
 
    [Register]
    * * User submits registration from
        
        * Frontend detects invalid format of one or more credentials.
            * UI indicators expresses to the user that the credentials provided are invalid to send the backend.
            * * [End]
        
        * UI indicators expresses to the user that the credentials provided are valid to send the backend.

        * A request is sent to the backend and the response is handled.

            * [403] registration failed because the account already exists.
            * * Inform the user why the request failed so they can make changes.
            * * [End]

            * [200] registration was successful.
            * * Redirect to Login fill automatically fill credentials and trigger Login action.
            * * [END]

    
    

    [Login]
    * * User submits login form
        
        * Frontend detects invalid format of one or more credentials.
            * UI indicators expresses to the user that the credentials provided are invalid to send the backend.
            * * [End]

        * UI indicators express to the user that the credentials provided are valid to send the backend.

        * A request is sent to the backend and the response is handled.
            * [200] login was successful
            * * Store authentication token and other data provided by the response.
            * * [End]

            * [403] login was successful but the account's email in unverifed
            * * Inform the user that their email is unverified.
            * * Redirect to [EmailVerification]
            * * [End]

            * [401] Login was unsucessful.
            * * Inform the user the provided credentials are invalid or the account does not exist.
            * * [End]



    [EmailVerification]
    * Is required to perform any authorized action.

    * Is already verified
    * * [End]

    * Upon loading determine if the user has been sent an email verfication.

        * Confirmation Input Box Always Active
        
        * Yes -> Inform the user they already have an email verification request pending or allow them to send another email verification.
        
        * No -> Automatically trigger the backend to send an email for verfication and inform the user to check their email.

    * User submits the verication confirmation value

    * A request is sent to the backend and the response is handled.
        * [200] Email confirmation was successful.
        * * [END]

        * [401] Email confirmation was unsuccessful. 
        * * Inform the user the provided confirmation value was invalid.
        * * [End]

