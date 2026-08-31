import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import core from "@actions/core";
import { UALogin, getRawSecrets, oidcLogin } from "./infisical.js";

try {
  var method = core.getInput("method");
  var domain = core.getInput("domain");
  var envSlug = core.getInput("env-slug");
  var projectSlug = core.getInput("project-slug");
  var secretPath = core.getInput("secret-path");
  var exportType = core.getInput("export-type");
  var fileOutputPath = core.getInput("file-output-path");
  var shouldIncludeImports = core.getBooleanInput("include-imports");
  var shouldRecurse = core.getBooleanInput("recursive");
  var unmaskWithTag = core.getInput("unmask-with-tag");
  var ifNotFound = core.getInput("if-not-found");

  // Validate ifNotFound input
  const validIfNotFoundOptions = ["warn", "error", "ignore"];
  if (!validIfNotFoundOptions.includes(ifNotFound)) {
    throw new Error(
      `Invalid value for if-not-found: ${ifNotFound}. Valid options are ${validIfNotFoundOptions.join(", ")}.`
    );
  }
} catch (error) {
  core.error("Failure during inputs validation");
  core.setFailed(error.message);
  throw error;
}

/**
 * Fetch Infisical Token using given given method
 * @param {string} _method Method name 
 */
const fetchInfisicalToken = async (method) => {
  switch (method) {
    case "universal": {
      const clientId = core.getInput("client-id");
      const clientSecret = core.getInput("client-secret");

      if (!(clientId && clientSecret)) {
        throw new Error("Missing universal auth credentials");
      }

      return await UALogin({
        domain,
        clientId,
        clientSecret,
      });
    }

    case "oidc": {
      const identityId = core.getInput("identity-id");
      const oidcAudience = core.getInput("oidc-audience");

      if (!identityId) {
        throw new Error("Missing identity ID");
      }

      return await oidcLogin({
        domain,
        identityId,
        oidcAudience,
      });
    }

    default:
      throw new Error("Invalid authentication method");
  }
};

/**
 * Mask secrets (if needed)
 * @param {Map<string, string>} secretsMap Secrets map
 */
const maskSecrets = (secretsMap) => {
  Object.entries(secretsMap).forEach(([key, secret]) => {
    if (unmaskWithTag == "" || !secret.tags.includes(unmaskWithTag)) {
      // only set secret if it's not unmasked
      if (secret.value == "") {
        core.debug(`Not masking ${key} - empty value`)
      } else {
        core.debug(`Masking ${key}...`);
        core.setSecret(secret.value);
      }
    } else {
      core.debug(`Not masking ${key} - unmask tag`)
    }
  });
}

/**
 * Export given secrets to environment variables
 * @param {Map<string, string>} secretsMap Secrets map
 */
const exportToEnvs = (secretsMap) => {
  core.debug("Exporting to environment variables...");

  Object.entries(secretsMap).forEach(([key, secret]) => {
    core.debug(`Exporting ${key}...`);
    core.exportVariable(key, secret.value);
    core.debug("OK");
  });

  core.info("Successfully exported secrets to env vars");
};

/**
 * Export given secrets to single file
 * @param {Map<string, string>} secretsMap Secrets map
 * @param {string} filePath File path
 */
const exportToSingleFile = (secretsMap, filePath) => {
  core.debug("Exporting to single file...");

  const isJson = filePath.endsWith('.json');

  let fileContent = '';
  if (isJson) {
    core.debug('File path ends with .json - exporting in JSON format');
    fileContent = JSON.stringify(
      Object.fromEntries(
        Object.entries(secretsMap).map(([key, secret]) => [key, secret.value])
      ),
      null,
      2
    );
  } else {
    core.debug('Exporting in k=v format');
    fileContent = Object.keys(secretsMap)
      .map((key) => `${key}='${secretsMap[key].value}'`)
      .join("\n");
  }

  try {
    fs.writeFileSync(filePath, fileContent);
  } catch (err) {
    core.setFailed(`Error writing file: ${err.message}`);
  }

  core.info("Successfully exported secrets to file");
};

/**
 * Export given secrets to a directory as a separate files
 * @param {Map<string, string>} secretsMap Secrets map
 * @param {string} dirPath Directory path
 */
const exportToSeparateFiles = (secretsMap, dirPath) => {
  core.debug("Exporting to separate files...");
  fs.mkdirSync(dirPath, { recursive: true });

  Object.entries(secretsMap).forEach(([key, secret]) => {
    const fileName = key.replace(/[\\/]/g, "_");
    const keyFile = path.join(dirPath, fileName);
    core.debug(`Saving ${key} to ${keyFile}...`);

    try {
      fs.writeFileSync(keyFile, secret.value, { mode: 0o600 });
      core.debug("OK");
    } catch (err) {
      throw new Error(`Error writing file '${keyFile}': ${err.message}`);
    }
  });

  core.info("Successfully exported secrets to separate files");
};


// Main
try {
  core.debug("Fetching Infisical Token...")
  const infisicalToken = await fetchInfisicalToken(method, domain);
  core.debug("OK");

  core.debug("Fetching secrets from Infisical...");
  const secretsMap = await getRawSecrets({
    domain,
    envSlug,
    infisicalToken,
    projectSlug,
    secretPath,
    shouldIncludeImports,
    shouldRecurse,
    ifNotFound
  });
  core.debug(`OK, fetched following keys: ${JSON.stringify(Object.keys(secretsMap))}`);

  maskSecrets(secretsMap);

  if (exportType === "env") {
    exportToEnvs(secretsMap);
    
  } else if (exportType === "file" || exportType === "files") {
    core.debug("Normalizing file output path...")
    fileOutputPath = path.normalize(fileOutputPath);
    core.debug(`OK - ${fileOutputPath}`);

    if (path.isAbsolute(fileOutputPath)) {
      core.debug('Provided file output path is absolute - checking....');
      if (fileOutputPath.startsWith(os.homedir())) {
        core.debug('Absolute file path is part of home directory - OK');
      } else {
        core.setFailed(`Security Validation! File output path you have provided is an absolute escaping your home directory. Please use either relative path or one inside ${os.homedir()}`);
      }
    } else {
      core.debug('An relative path - placing in workspace');
      fileOutputPath = path.join(process.env.GITHUB_WORKSPACE, fileOutputPath);
    }

    core.debug(`File path is: ${fileOutputPath}`)

    if (exportType === "files") {
      // Export each secret as a separate file
      exportToSeparateFiles(secretsMap, fileOutputPath);
    } else {
      // Single file with all secrets
      exportToSingleFile(secretsMap, fileOutputPath);
    }

  } else {
    core.setFailed("Unsupported exportType!")
  }
} catch (error) {
  core.setFailed(error.message);
}
