
Define Outline for Blog Branch 0.1.1

Split features up into branch versions for easy completion and easy rollbacks.


Blog Web:
 * set current working branch as 0.1.0
 * Define outline for Blog Branch 0.1.1
 * Should match features of Blog API 0.1.1




Dont try to accomplish all features in version 0.1.1. 
Focus on the next single most important feature for overall completion

Authentication 
 * Registration
 * Email Verification
 * Forgot Password
 * Email Reset Password






Website

 * General Registration
 * * Email verification
 * * Reset Password Feature

 * Dashboard for each user
 * Admin Dashboard if Admin (Analytics)

 * Pagenation implementation of posts and comments
 * Pages of 25 for posts
 * Scrolling (Show More) feature for comments.


Backend

 * Create User
 * * Email Verification
 * * require_token (Update to include verifcation status)

 * Reset Password
 * * Generate one-time token to reset password
 * * Website specialization
 * * Generates link with embbedded token 
 * * Requester sends email to use as reset and sends a target link for email url generation. 
 * * Sends Link to emai


Forgot Password -> Email -> Submit -> 
Send Email and Link to return to for password reset -> Backend Recieves Request ->
generates one-time token for password reset -> appends to ReturnToLink -> 
sends to email -> Email Recieved -> Click Generated Reset Password Link w/ embedded token ->
Redirects to Website -> Sends token for verification -> Verification success -> 
Show new password / confirm password fields -> Submit -> sends to backend ->
backend recieves the request -> Verifies token -> Updates users password field ->
Revokes Token from being used again. -> Forwards response to website -> 
Website navigates to Login Screen
