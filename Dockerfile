# syntax=docker/dockerfile:1
# Interdimensional Rift development/runtime image.
# This image is NOT the hostile-code security boundary. Untrusted execution uses
# tools/run-rift-bwrap.sh on a Linux host. The frozen trusted Dalamud runtime is
# supplied separately as a read-only contract directory.

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY InterdimensionalRift/InterdimensionalRift.csproj InterdimensionalRift/
RUN dotnet restore InterdimensionalRift/InterdimensionalRift.csproj
COPY InterdimensionalRift/ InterdimensionalRift/
RUN dotnet publish InterdimensionalRift/InterdimensionalRift.csproj \
    -c Release -o /app --no-restore /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app .
RUN useradd --create-home --shell /bin/bash rift
USER rift
WORKDIR /home/rift
ENTRYPOINT ["dotnet", "/app/interdimensional-rift.dll"]
CMD ["--help"]
