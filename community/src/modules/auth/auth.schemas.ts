import { z } from "zod";

const emailSchema = z
  .string()
  .trim()
  .email()
  .max(254)
  .transform((value) => value.toLowerCase());

const usernameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(30)
  .regex(
    /^[a-z0-9_][a-z0-9._]{1,28}[a-z0-9_]$/,
    "Username must contain only lowercase letters, numbers, dots or underscores"
  );

const passwordSchema = z
  .string()
  .min(12, "Password must contain at least 12 characters")
  .max(128, "Password cannot exceed 128 characters");

export const signupSchema = z
  .object({
    email: emailSchema,
    username: usernameSchema,
    password: passwordSchema
  })
  .strict();

export const loginSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1).max(128)
  })
  .strict();

export const refreshSchema = z.object({}).strict();

export const logoutSchema = z.object({}).strict();

export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;

export const verifyEmailSchema = z
  .object({
    token: z.string().regex(/^[A-Za-z0-9_-]{43}$/)
  })
  .strict();

export const resendVerificationSchema = z
  .object({
    email: emailSchema
  })
  .strict();
