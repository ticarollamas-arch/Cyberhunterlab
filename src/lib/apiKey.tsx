import React, { createContext, useContext, useState, useEffect } from 'react';

interface ApiKeyContextType {
  apiKey: string | null;
  setApiKey: (key: string | null) => void;
  isConfigured: boolean;
}

const ApiKeyContext = createContext<ApiKeyContextType | undefined>(undefined);

export function ApiKeyProvider({ children }: { children: React.ReactNode }) {
  const [apiKey, setApiKey] = useState<string | null>(() => {
    return sessionStorage.getItem('gemini_api_key');
  });

  const handleSetApiKey = (key: string | null) => {
    if (key) {
      sessionStorage.setItem('gemini_api_key', key);
    } else {
      sessionStorage.removeItem('gemini_api_key');
    }
    setApiKey(key);
  };

  const isConfigured = !!apiKey;

  return (
    <ApiKeyContext.Provider value={{ apiKey, setApiKey: handleSetApiKey, isConfigured }}>
      {children}
    </ApiKeyContext.Provider>
  );
}

export function useApiKey() {
  const context = useContext(ApiKeyContext);
  if (context === undefined) {
    throw new Error('useApiKey must be used within an ApiKeyProvider');
  }
  return context;
}
