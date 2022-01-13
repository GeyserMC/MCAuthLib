# MCAuthLib
MCAuthLib is a library for authentication with Minecraft accounts. It is used in projects such as MCProtocolLib to handle authenticating users.

## Example Code
See [example/com/github/steveice10/mc/auth/test/MinecraftAuthTest.java](https://github.com/Steveice10/MCAuthLib/blob/master/example/com/github/steveice10/mc/auth/test/MinecraftAuthTest.java)

## Authentication Types

Visit [wiki.vg](https://wiki.vg/) for documentation on [Mojang API authentication](https://wiki.vg/Authentication) and [Microsoft's API authentication](https://wiki.vg/Microsoft_Authentication_Scheme).

| `AuthenticationService` | Usage |
| :---: | --- |
| `MojangAuthenticationService` | Used for authenticating Mojang accounts. Supports regular Mojang accounts (email) and legacy accounts (username). |
| `MsaAuthenticationService` | Used for authenticating Microsoft accounts. This service is a custom implementation using a combination of Microsoft, Mojang, and Xbox API's. |
| `MSALAuthenticationService` | Alternative service for authenticating Microsoft accounts. This service uses the [Microsoft Authentication Library (MSAL) for Java](https://github.com/AzureAD/microsoft-authentication-library-for-java) to authenticate. |

## Building the Source
MCAuthLib uses Maven to manage dependencies. Simply run 'mvn clean install' in the source's directory.

## Support and development

Please join us at https://discord.gg/geysermc under #mcprotocollib for discussion and support for this project.

## License
MCAuthLib is licensed under the **[MIT license](http://www.opensource.org/licenses/mit-license.html)**.

