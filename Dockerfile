# syntax=docker/dockerfile:1
#
# Interdimensional Rift development/runtime image.
#
# IMPORTANT: this image is not, by itself, the hostile-code security boundary.
# Untrusted execution is performed by tools/run-rift-bwrap.sh on a Linux host.
# The current generated Dalamud shim also needs its API-15 compatibility repair
# before this Dockerfile is considered a production build path.
#
# Two stages: SDK build → ASP.NET-free runtime image.

# ---- Build stage ----
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy only the project files first so the restore layer caches when
# only source changes. The rest of the source is copied below.
COPY InterdimensionalRift.sln ./
COPY InterdimensionalRift.DalamudShim/InterdimensionalRift.DalamudShim.csproj InterdimensionalRift.DalamudShim/
COPY InterdimensionalRift/InterdimensionalRift.csproj InterdimensionalRift/
COPY samples/SamplePlugin/SamplePlugin.csproj samples/SamplePlugin/
COPY tests/InterdimensionalRift.Tests/InterdimensionalRift.Tests.csproj tests/InterdimensionalRift.Tests/

RUN dotnet restore InterdimensionalRift.sln

COPY . .

RUN dotnet publish InterdimensionalRift/InterdimensionalRift.csproj \
        -c Release \
        -o /app \
        --no-restore \
        /p:UseAppHost=false

# ---- Runtime stage ----
# The rift has no UI dependency, no native code, no web hosting.
# The plain .NET 10 runtime image is enough.
FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app

COPY --from=build /app .

# The rift reads a plugin path from argv and writes JSON to stdout
# or to the --out path. Running as non-root keeps the surface small.
RUN useradd --create-home --shell /bin/bash rift
USER rift
WORKDIR /home/rift

ENTRYPOINT ["dotnet", "/app/interdimensional-rift.dll"]
CMD ["--help"]
