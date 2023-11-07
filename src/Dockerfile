# pull .NET SDK 8.0 image
FROM mcr.microsoft.com/dotnet/sdk:8.0 as build
ARG TARGETARCH=linux-x64
ARG SELFCONTAINED=true
ARG SINGLEFILE=true
WORKDIR /source

# copy all csproj files
COPY nsec/src/Cryptography/*.csproj nsec/src/Cryptography/
COPY yae/src/Yae.Core/*.csproj yae/src/Yae.Core/
COPY EncryptedContainerFile/ECF.Test/*.csproj EncryptedContainerFile/ECF.Test/
COPY EncryptedContainerFile/ECF.CLI/*.csproj EncryptedContainerFile/ECF.CLI/
COPY EncryptedContainerFile/ECF.Core/*.csproj EncryptedContainerFile/ECF.Core/

# restore
RUN dotnet restore EncryptedContainerFile/ECF.CLI/ECF.CLI.csproj

# copy all content
COPY nsec/src/Cryptography/ nsec/src/Cryptography/
COPY nsec/src/Interop/ nsec/src/Interop/
COPY yae/src/Yae.Core/ yae/src/Yae.Core/
COPY EncryptedContainerFile/ECF.Test/ EncryptedContainerFile/ECF.Test/
COPY EncryptedContainerFile/ECF.CLI/ EncryptedContainerFile/ECF.CLI/
COPY EncryptedContainerFile/ECF.Core/ EncryptedContainerFile/ECF.Core/


# build
RUN dotnet publish /source/EncryptedContainerFile/ECF.CLI -r $TARGETARCH --sc $SELFCONTAINED -p:PublishSingleFile=$SINGLEFILE --no-restore -o /app

