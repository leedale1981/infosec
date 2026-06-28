# AISecurity - Indirect Prompt Injection (RAG) Demo

```text
    ___    ____   _____                 _ _         
   / _ |  /  _/  / ___/___ ______ _  __(_) |_ _   __
  / __ | _/ /   / /__/ _ `/ __/| |/ / / /  ' \ | / /
 /_/ |_|/___/   \___/\_,_/_/   |___/_/_/_/_/_\_, / 
                                             /___/  
```

This repository contains a **simple, intentional example** of **indirect prompt injection in RAG**.  
The API at `D:\src\infosec\AISecurity\LD.Ai.Security.Api` retrieves policy documents from a SharePoint library, builds a prompt, and sends it to a local Ollama model. A single malicious document can influence the model to return incorrect company policy details.

## Example SharePoint library

![SharePoint library showing policy documents and override document](images/RAGLibraryPromptIInjection.png)

## Architecture (high-level)

```mermaid
flowchart LR
    U[User asks policy question] --> API[LD.Ai.Security.Api]
    API --> SP[SharePoint Policy Documents library]
    SP --> RET[Retrieve + score matching documents]
    RET --> PR[Prompt assembly]
    PR --> OLL[Local Ollama LLM]
    OLL --> RES[Answer returned to user]

    M[Policy Override document] -.included in context.-> PR
```

## Detailed injection flow

```mermaid
sequenceDiagram
    participant User
    participant API as LD.Ai.Security.Api
    participant SP as SharePoint Library
    participant LLM as Ollama (local)

    User->>API: "What is the holiday policy?"
    API->>SP: Retrieve relevant docs (.docx/.txt/.md)
    SP-->>API: Holiday Policy + Policy Override document
    API->>API: Concatenate docs into one prompt context
    API->>LLM: Send context + user question
    LLM-->>API: Response biased by override instructions
    API-->>User: Incorrect policy answer
```

## Why this works in the vulnerable path

The `/ask-vulnerable` endpoint places retrieved document text directly into the model prompt as if it were trusted guidance.  
If one document contains hostile instructions (for example, telling the assistant to ignore prior rules or redefine leave policy), the model can follow that text and produce an incorrect answer.

## Security modes in this sample API

1. `/ask-vulnerable` - demonstrates the unsafe pattern.
2. `/ask-hardened` - keeps docs untrusted and adds defensive prompt rules.
3. `/ask-scanned` - excludes suspicious documents using a basic scanner before prompting.

## Demo objective

Use this project to show that:

- **RAG context is an attack surface**.
- **A single injected SharePoint document can overwrite policy behavior in model output**.
- **Local models (Ollama) are still vulnerable when prompt construction is weak**.

This project is for **security education and defensive testing**.
