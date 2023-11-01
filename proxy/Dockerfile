FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build

WORKDIR /app

COPY /proxy.csproj /app/proxy.csproj

RUN dotnet restore

COPY . .

RUN dotnet build \
    && dotnet publish -c Release -o /build --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:7.0

WORKDIR /app

COPY --from=build /build ./

ENTRYPOINT ["dotnet", "./proxy.dll"]