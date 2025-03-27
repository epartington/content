## About AI Runtime Security API Intercept
AI Runtime Security: API Intercept is a threat detection service designed to secure AI applications. It helps discover and protect applications using REST APIs by embedding Security-as-Code directly into source code.

The scan API service scans prompt and responses in real-time to identify potential threats and provide threat assessments with actionable recommendations. These APIs protect your AI models, AI applications, and AI datasets by programmatically scanning prompts and models for threats, enabling robust protection across public and private models with model-agnostic functionality.

For licensing, onboarding, activation, and to obtain the API authentication key and profile name, refer to the AI Runtime Security: API Intercept Overview administration documentation.

### Limitations
  - One AI security profile per Tenant Service Group (TSG) - Limited to one security profile per group.
  - One API key per deployment profile - Each deployment profile in the Customer Support Portal allows a single API key.
  - 2 MB maximum payload size per synchronous scan request - Limited to a maximum of 100 URLs per request.
  - 5 MB maximum payload size per asynchronous scan request - Limited to a maximum of 100 URLs per request.

---
[View Integration Documentation](https://pan.dev/ai-runtime-security/scan/api/)