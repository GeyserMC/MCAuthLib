# MCAuthLib
MCAuthLib is a library for authentication with Minecraft accounts. It is used in projects such as [MCProtocolLib](https://github.com/GeyserMC/MCProtocolLib) to handle authenticating users.

## Example Code
See [example/com/github/steveice10/mc/auth/test/MinecraftAuthTest.java](https://github.com/GeyserMC/MCAuthLib/blob/master/example/com/github/steveice10/mc/auth/test/MinecraftAuthTest.java) for example usage.

## Installing as a dependency
Most developers should be using MCAuthLib through MCProtocolLib, but you can also use it independently. The recommended way of installing MCAuthLib is through [JitPack](https://jitpack.io). For more details, [see MCAuthLib on JitPack](https://jitpack.io/#Steveice10/MCAuthLib).

Maven:
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependency>
    <groupId>com.github.Steveice10</groupId>
    <artifactId>MCAuthLib</artifactId>
    <version>(version here)</version>
</dependency>
```

Gradle:
```groovy
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}

dependencies {
    implementation 'com.github.Steveice10:MCAuthLib:(version here)'
}
```

## Building the source
MCAuthLib uses Maven to manage dependencies. To build the source code, run `mvn clean install` in the project root directory.

## Support and development
Please join [our Discord server](https://discord.gg/geysermc) and visit the **#mcprotocollib** channel for discussion and support for this project.

## License
MCAuthLib is licensed under the **[MIT license](http://www.opensource.org/licenses/mit-license.html)**.
