# Testing Guide

Manual test cases can be executed through the Streamlit UI after running `make up`.

## 1. Benign URL
- URL Length: `Short`
- SSL Certificate Status: `Trusted`
- Sub-domain Complexity: `None`
- Prefix/Suffix: unchecked
- Uses IP Address: unchecked
- Shortened URL: unchecked
- Contains `@` symbol: unchecked
- Abnormal URL: unchecked
- Contains political keyword: unchecked

**Expected:** URL classified as Benign. Threat Attribution tab notes that attribution is only for malicious URLs.

## 2. State-Sponsored Profile
- URL Length: `Long`
- SSL Certificate Status: `Trusted`
- Sub-domain Complexity: `Many`
- Prefix/Suffix: checked
- Uses IP Address: unchecked
- Shortened URL: unchecked
- Contains `@` symbol: unchecked
- Abnormal URL: checked
- Contains political keyword: unchecked

**Expected:** URL classified as Malicious with actor profile **State-Sponsored**.

## 3. Organized Cybercrime Profile
- URL Length: `Long`
- SSL Certificate Status: `None`
- Sub-domain Complexity: `Many`
- Prefix/Suffix: checked
- Uses IP Address: checked
- Shortened URL: checked
- Contains `@` symbol: checked
- Abnormal URL: checked
- Contains political keyword: unchecked

**Expected:** URL classified as Malicious with actor profile **Organized Cybercrime**.

## 4. Hacktivist Profile
- URL Length: `Long`
- SSL Certificate Status: `Suspicious`
- Sub-domain Complexity: `One`
- Prefix/Suffix: checked
- Uses IP Address: unchecked
- Shortened URL: unchecked
- Contains `@` symbol: unchecked
- Abnormal URL: checked
- Contains political keyword: checked

**Expected:** URL classified as Malicious with actor profile **Hacktivist**.
