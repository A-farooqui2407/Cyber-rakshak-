import React, { createContext, useContext, useEffect, useState } from "react";
import { UserRole, UserProfile } from "../types";
import { api } from "../services/api";

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  role: UserRole;
  organization: string;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  canPerformAction: (requiredRole: UserRole) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("cyberrakshak_token");
    if (!token) {
      setReady(true);
      return;
    }
    api
      .me()
      .then((res) => setUser(res.user))
      .catch(() => {
        localStorage.removeItem("cyberrakshak_token");
        setUser(null);
      })
      .finally(() => setReady(true));
  }, []);

  const login = async (email: string, password: string) => {
    const res = await api.login(email, password);
    localStorage.setItem("cyberrakshak_token", res.token);
    setUser(res.user);
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("cyberrakshak_token");
  };

  const canPerformAction = (requiredRole: UserRole): boolean => {
    if (!user) return false;
    if (user.role === "ADMIN") return true;
    if (user.role === "ANALYST" && (requiredRole === "ANALYST" || requiredRole === "VIEWER")) return true;
    if (user.role === "VIEWER" && requiredRole === "VIEWER") return true;
    return false;
  };

  if (!ready) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center text-slate-400 text-sm font-mono">
        Restoring SOC session…
      </div>
    );
  }

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        role: user ? user.role : "VIEWER",
        organization: user?.organization || "LexGuard Law Associates",
        login,
        logout,
        canPerformAction,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
};
