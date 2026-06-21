import { create } from 'zustand';
import type { User, AuthTokens } from '../types';
import { api, setAccessToken, setRefreshToken, clearTokens, getAccessToken } from '../services/api';

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, remember?: boolean) => Promise<void>;
  register: (email: string, password: string, name: string, role: string, remember?: boolean) => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: !!getAccessToken(),
  isLoading: true,

  login: async (email, password, remember = true) => {
    const data = await api.auth.login(email, password);
    setAccessToken(data.access_token, remember);
    setRefreshToken(data.refresh_token, remember);
    localStorage.setItem('remember_me', String(remember));
    set({ user: data.user, isAuthenticated: true });
  },

  register: async (email, password, name, role, remember = true) => {
    const data = await api.auth.register(email, password, name, role);
    setAccessToken(data.access_token, remember);
    setRefreshToken(data.refresh_token, remember);
    localStorage.setItem('remember_me', String(remember));
    set({ user: data.user, isAuthenticated: true });
  },

  logout: () => {
    clearTokens();
    set({ user: null, isAuthenticated: false });
  },

  checkAuth: async () => {
    try {
      if (getAccessToken()) {
        const user = await api.auth.me();
        set({ user, isAuthenticated: true, isLoading: false });
      } else {
        set({ isLoading: false });
      }
    } catch {
      clearTokens();
      set({ user: null, isAuthenticated: false, isLoading: false });
    }
  },
}));
