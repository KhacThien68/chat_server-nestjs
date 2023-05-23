import { User } from '@prisma/client';
import { Token } from '../entities';

export class AuthResponse {
  token: Promise<Token>;
  status: number;
  user: User;
}
