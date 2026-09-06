import React, { createContext, useContext, useState, useEffect } from 'react';
import { apiService, User, UserRole } from '../services/api';

export interface CurrentUser {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  badgeId: string;
}

interface UserContextType {
  user: User | null;
  currentUser: CurrentUser;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessionExpired: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (fullName: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  clearSessionExpired: () => void;
  filterMode: 'MY_CASES' | 'ALL_CASES';
  setFilterMode: (mode: 'MY_CASES' | 'ALL_CASES') => void;
  assignedCaseIds: string[];
  assignCaseToUser: (caseId: string) => void;
  isCaseAssigned: (caseId: string) => boolean;
}

const ANONYMOUS_USER: CurrentUser = {
  id: '',
  name: 'Not Authenticated',
  email: '',
  role: 'INVESTIGATOR',
  badgeId: 'EMIT-OFFLINE',
};

const UserContext = createContext<UserContextType | undefined>(undefined);

export const UserProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => localStorage.getItem('emit_auth_token'));
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);
  const [filterMode, setFilterMode] = useState<'MY_CASES' | 'ALL_CASES'>('MY_CASES');
  const [assignedCaseIds, setAssignedCaseIds] = useState<string[]>([]);

  // Map user to CurrentUser for backwards compatibility across existing pages
  const currentUser: CurrentUser = user
    ? {
        id: user.user_id,
        name: user.full_name,
        email: user.email,
        role: user.role,
        badgeId: user.badge_id,
      }
    : ANONYMOUS_USER;

  // Restore authenticated session on mount if token exists
  useEffect(() => {
    let isMounted = true;

    const restoreSession = async () => {
      const savedToken = localStorage.getItem('emit_auth_token');
      if (!savedToken) {
        if (isMounted) setIsLoading(false);
        return;
      }

      try {
        const profile = await apiService.getMe();
        if (isMounted) {
          setUser(profile);
          setToken(savedToken);
        }
      } catch (err) {
        // Token invalid or session revoked
        localStorage.removeItem('emit_auth_token');
        if (isMounted) {
          setUser(null);
          setToken(null);
        }
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    restoreSession();

    // Listen for unauthorized 401 events dispatched by Axios interceptor
    const handleUnauthorized = () => {
      if (isMounted) {
        setUser(null);
        setToken(null);
        setSessionExpired(true);
      }
    };

    window.addEventListener('emit-auth-unauthorized', handleUnauthorized);
    return () => {
      isMounted = false;
      window.removeEventListener('emit-auth-unauthorized', handleUnauthorized);
    };
  }, []);

  const login = async (email: string, password: string) => {
    const res = await apiService.login({ email, password });
    localStorage.setItem('emit_auth_token', res.access_token);
    setToken(res.access_token);
    setUser(res.user);
    setSessionExpired(false);
  };

  const signup = async (fullName: string, email: string, password: string) => {
    const res = await apiService.signup({ full_name: fullName, email, password });
    localStorage.setItem('emit_auth_token', res.access_token);
    setToken(res.access_token);
    setUser(res.user);
    setSessionExpired(false);
  };

  const logout = async () => {
    try {
      await apiService.logout();
    } catch {
      // Proceed even if server is unreachable
    } finally {
      localStorage.removeItem('emit_auth_token');
      setToken(null);
      setUser(null);
      setSessionExpired(false);
    }
  };

  const clearSessionExpired = () => {
    setSessionExpired(false);
  };

  const assignCaseToUser = (caseId: string) => {
    setAssignedCaseIds((prev) => (prev.includes(caseId) ? prev : [...prev, caseId]));
  };

  const isCaseAssigned = (caseId: string): boolean => {
    if (!caseId) return false;
    if (user?.role === 'ADMIN') return true;
    return true; // Backend enforces true isolation
  };

  return (
    <UserContext.Provider
      value={{
        user,
        currentUser,
        token,
        isAuthenticated: !!user,
        isLoading,
        sessionExpired,
        login,
        signup,
        logout,
        clearSessionExpired,
        filterMode,
        setFilterMode,
        assignedCaseIds,
        assignCaseToUser,
        isCaseAssigned,
      }}
    >
      {children}
    </UserContext.Provider>
  );
};

export const useUser = (): UserContextType => {
  const context = useContext(UserContext);
  if (!context) {
    throw new Error('useUser must be used within a UserProvider');
  }
  return context;
};

export default UserContext;
