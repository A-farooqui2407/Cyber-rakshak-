import React, { createContext, useContext, useState, useEffect } from "react";
import { UserRole, UserProfile } from "../types";

interface AuthContextType {
  user: UserProfile | null;
  isAuthenticated: boolean;
  role: UserRole;
  organization: string;
  login: (role?: UserRole) => void;
  logout: () => void;
  switchRole: (newRole: UserRole) => void;
  switchOrganization: (newOrg: string) => void;
  canPerformAction: (requiredRole: UserRole) => boolean;
}

const DEFAULT_USERS: Record<UserRole, UserProfile> = {
  ADMIN: {
    id: "22222222-2222-2222-2222-222222222221",
    name: "Rahul Sharma",
    email: "rahul.sharma@lexguard.com",
    role: "ADMIN",
    organization: "LexGuard Law Associates",
  },
  ANALYST: {
    id: "22222222-2222-2222-2222-222222222222",
    name: "Ananya Patel",
    email: "ananya.p@lexguard.com",
    role: "ANALYST",
    organization: "LexGuard Law Associates",
  },
  VIEWER: {
    id: "22222222-2222-2222-2222-222222222223",
    name: "Vikram Singh",
    email: "vikram.s@lexguard.com",
    role: "VIEWER",
    organization: "LexGuard Law Associates",
  },
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(() => {
    const savedRole = localStorage.getItem("cyberrakshak_role") as UserRole;
    return DEFAULT_USERS[savedRole] || DEFAULT_USERS.ADMIN;
  });

  const [organization, setOrganization] = useState<string>("LexGuard Law Associates");

  useEffect(() => {
    if (user) {
      localStorage.setItem("cyberrakshak_role", user.role);
    }
  }, [user]);

  const login = (role: UserRole = "ADMIN") => {
    setUser(DEFAULT_USERS[role]);
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("cyberrakshak_role");
  };

  const switchRole = (newRole: UserRole) => {
    setUser(DEFAULT_USERS[newRole]);
  };

  const switchOrganization = (newOrg: string) => {
    setOrganization(newOrg);
    if (user) {
      setUser({ ...user, organization: newOrg });
    }
  };

  const canPerformAction = (requiredRole: UserRole): boolean => {
    if (!user) return false;
    if (user.role === "ADMIN") return true;
    if (user.role === "ANALYST" && (requiredRole === "ANALYST" || requiredRole === "VIEWER")) return true;
    if (user.role === "VIEWER" && requiredRole === "VIEWER") return true;
    return false;
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        role: user ? user.role : "VIEWER",
        organization,
        login,
        logout,
        switchRole,
        switchOrganization,
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
