group "default" {
  targets = ["tsn"]
}

target "tsn" {
  dockerfile = "Dockerfile"
  platforms  = ["linux/amd64", "linux/arm64"]
  args = {
    FEATURES = "default,pq"
  }
  cache-from = ["type=gha"]
  cache-to   = ["type=gha,mode=max"]
  output = ["type=registry"]
}