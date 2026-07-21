import React, { createContext, useContext, useState, useEffect } from 'react';

export type GeminiModel = 'gemini-3.5-flash' | 'gemini-2.5-flash' | 'gemini-flash-latest' | 'gemini-3.1-pro-preview';

interface ApiKeyContextType {
  apiKey: string | null;
  setApiKey: (key: string | null) => void;
  isConfigured: boolean;
  selectedModel: GeminiModel;
  setSelectedModel: (model: GeminiModel) => void;
}

const ApiKeyContext = createContext<ApiKeyContextType | undefined>(undefined);

export function ApiKeyProvider({ children }: { children: React.ReactNode }) {
  const [apiKey, setApiKey] = useState<string | null>(() => {
    return sessionStorage.getItem('gemini_api_key');
  });

  const [selectedModel, setSelectedModel] = useState<GeminiModel>(() => {
    return (sessionStorage.getItem('gemini_selected_model') as GeminiModel) || 'gemini-3.5-flash';
  });

  const handleSetApiKey = (key: string | null) => {
    if (key) {
      sessionStorage.setItem('gemini_api_key', key);
    } else {
      sessionStorage.removeItem('gemini_api_key');
    }
    setApiKey(key);
  };

  const handleSetSelectedModel = (model: GeminiModel) => {
    sessionStorage.setItem('gemini_selected_model', model);
    setSelectedModel(model);
  };

  const isConfigured = !!apiKey;

  return (
    <ApiKeyContext.Provider value={{ 
      apiKey, 
      setApiKey: handleSetApiKey, 
      isConfigured, 
      selectedModel, 
      setSelectedModel: handleSetSelectedModel 
    }}>
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
