/* eslint-disable @typescript-eslint/no-unused-vars */
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomBytes, scrypt as _scrypt } from 'crypto';
import { promisify } from 'util';
import { v4 as uuid } from 'uuid';

const scrypt = promisify(_scrypt);

const users = [];
const refreshTokens: { value: string }[] = [];

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  async signUp(email: string, password: string, roles: string[]) {
    const existingUser = users.find((user) => user.email === email);

    if (existingUser) {
      throw new UnauthorizedException('email in use');
    }

    const salt = randomBytes(8).toString('hex');
    const hash = (await scrypt(password, salt, 32)) as Buffer;
    const saltAndHash = `${salt}.${hash.toString('hex')}`;

    const user = {
      id: uuid(),
      email,
      password: saltAndHash,
      roles,
    };

    users.push(user);

    const { password: _, ...result } = user;

    return result;
  }

  async signIn(email: string, password: string) {
    const user = users.find((user) => user.email === email);

    if (!user) throw new UnauthorizedException('invalid credentials');

    const [salt, storedHash] = user.password.split('.');

    const hash = (await scrypt(password, salt, 32)) as Buffer;

    if (storedHash !== hash.toString('hex')) {
      throw new UnauthorizedException('invalid credentials');
    }

    return this.generateTokens(user);
  }

  async refresh(refreshToken: string) {
    const storedToken = refreshTokens.find(
      (token) => token.value === refreshToken,
    );

    if (!storedToken) {
      throw new UnauthorizedException('invalid token');
    }

    const payload = this.jwtService.verify(refreshToken);

    if (payload.type !== 'refresh') {
      throw new UnauthorizedException('invalid token');
    }

    const user = users.find((user) => user.id === payload.sub);

    if (!user) {
      throw new UnauthorizedException('invalid token');
    }

    return this.generateTokens(user, refreshToken);
  }

  private generateTokens(user, previousToken?: string) {
    const payload = {
      username: user.email,
      sub: user.id,
      roles: user.roles,
    };

    const accessToken = this.jwtService.sign(
      { ...payload, type: 'access' },
      { expiresIn: '60s' },
    );

    const refreshToken = this.jwtService.sign(
      { ...payload, type: 'refresh' },
      { expiresIn: '1h' },
    );

    const storedToken = previousToken
      ? refreshTokens.find((token) => token.value === previousToken)
      : null;

    if (!storedToken) {
      refreshTokens.push({ value: refreshToken });
    } else {
      storedToken.value = refreshToken;
    }

    return { accessToken, refreshToken };
  }
}
