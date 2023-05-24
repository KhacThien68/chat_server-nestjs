import { User } from '@prisma/client';
import { Token } from '../entities';

export class AuthResponse {
  token: Token;
  status: number;
  user: User;
}
