# Insomnia template tag for HMAC signature of message or request body (Bruno version)

Based on the [Insomnia template tag for HMAC signature of message or request body](https://github.com/grunka/insomnia-plugin-request-body-hmac) published to NPM.

For the nice rest client [Insomnia](https://insomnia.rest)

Main feature is being able to generate HMAC signatures from a key and a message, where the message can be the request body content. 

The signature can be inserted into the url, request parameters, headers, and request body itself. That last one is probably only useful in combination of doing the signature using a portion of the request body selected by JSONPath. Also has an option of removing whitespace from a JSON request body before calculating the signature.