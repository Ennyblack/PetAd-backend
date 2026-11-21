import { Controller, Get, Param, Post, UseGuards, Req } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { Role } from '../auth/enums/role.enum';
import { CheckPolicy } from '../common/policies/check-policy.decorator';
import { PolicyAction, PolicySubject } from '../common/policies/policy.types';
import { DocumentsService } from './documents.service';

interface AuthRequest extends Request {
  user: {
    userId?: string;
    sub?: string;
    role?: string;
  };
}

@ApiTags('Documents')
@ApiBearerAuth('JWT-auth')
@Controller('documents')
export class DocumentsController {
  constructor(private readonly documentsService: DocumentsService) {}

  @Post(':id/verify-integrity')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({
    summary: 'Verify document integrity (Admin only)',
    description: 'Re-hashes the stored object and reports match/mismatch.',
  })
  @ApiParam({ name: 'id', description: 'Document ID' })
  @ApiResponse({ status: 200, description: 'Integrity verified' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  @ApiResponse({ status: 404, description: 'Document not found' })
  verifyIntegrity(@Param('id') id: string, @Req() req: AuthRequest) {
    const actorId = req.user?.userId ?? req.user?.sub ?? 'admin';
    return this.documentsService.verifyIntegrity(id, actorId);
  }

  @Get(':id')
  @UseGuards(JwtAuthGuard)
  @CheckPolicy(PolicyAction.READ, PolicySubject.DOCUMENT)
  @ApiOperation({
    summary: 'Get a document',
    description:
      'Readable by its uploader, the parties of the related adoption, or an admin. ' +
      'Any other caller gets 404 so the document is not disclosed.',
  })
  @ApiParam({ name: 'id', description: 'Document ID' })
  @ApiResponse({ status: 200, description: 'Document found' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'Document not found' })
  getDocument(@Param('id') id: string) {
    return this.documentsService.findOne(id);
  }
}
