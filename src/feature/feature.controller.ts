import { Controller, Get, UseGuards } from '@nestjs/common';
import { CurrentUser } from 'src/auth/current-user.decorator';
import { CurrentUserDto } from 'src/auth/current-user.dto';
import { JwtAuthGuard } from 'src/auth/jwt-auth.guard';
import { Roles } from 'src/auth/roles-decorator';

@Controller('feature')
export class FeatureController {
  @Get('public')
  getPublicFeature() {
    return 'this is a public feature';
  }

  @Get('private')
  @UseGuards(JwtAuthGuard)
  getPrivateFeature(@CurrentUser() user: CurrentUserDto) {
    return `this is a private feature, user: ${user.username}`;
  }

  @Get('admin')
  @Roles('admin')
  @UseGuards(JwtAuthGuard)
  getAdminFeature() {
    return 'this is a admin-only feature';
  }
}
