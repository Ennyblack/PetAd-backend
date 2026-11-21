import {
  Injectable,
  NotFoundException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CloudinaryService } from '../cloudinary/cloudinary.service';
import { EventsService } from '../events/events.service';
import { UserRole } from '@prisma/client';
const EventEntityType = { DOCUMENT: 'DOCUMENT' } as any;
const EventType = { DOCUMENT_VERIFIED: 'DOCUMENT_VERIFIED', DOCUMENT_UPLOADED: 'DOCUMENT_UPLOADED' } as any;
import * as crypto from 'crypto';

@Injectable()
export class DocumentsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly cloudinary: CloudinaryService,
    private readonly eventsService: EventsService,
  ) {}

  /**
   * Loads a single document.
   * Resource-level authorization is enforced by PoliciesGuard before this runs.
   *
   * @throws NotFoundException if the document does not exist
   */
  async findOne(documentId: string) {
    const document = await this.prisma.document.findUnique({
      where: { id: documentId },
      include: {
        adoption: {
          select: { id: true, petId: true, adopterId: true, ownerId: true },
        },
      },
    });

    if (!document) {
      throw new NotFoundException('Document not found');
    }

    return document;
  }

  async verifyIntegrity(documentId: string, actorId: string) {
    const document = await this.prisma.document.findUnique({
      where: { id: documentId },
    });

    if (!document) {
      throw new NotFoundException('Document not found');
    }

    let currentHash = '';
    try {
      const response = await fetch(document.fileUrl);
      if (!response.ok || !response.body) {
        throw new Error(`Failed to fetch document file from storage: ${response.statusText}`);
      }
      const hashStream = crypto.createHash('sha256');
      const nodeStream = require('stream').Readable.fromWeb(response.body as any);
      await new Promise((resolve, reject) => {
        nodeStream.pipe(hashStream);
        nodeStream.on('error', reject);
        hashStream.on('finish', resolve);
      });
      currentHash = hashStream.digest('hex');
    } catch (err) {
      throw new BadRequestException('Could not retrieve stored file to verify integrity');
    }

    const storedHash = document.sha256;
    const match = storedHash ? currentHash === storedHash : false;

    await this.eventsService.logEvent({
      entityType: EventEntityType.DOCUMENT,
      entityId: document.id,
      eventType: EventType.DOCUMENT_VERIFIED,
      actorId,
      payload: {
        documentId: document.id,
        storedHash,
        currentHash,
        match,
      },
    });

    return {
      documentId: document.id,
      storedHash,
      currentHash,
      match,
      status: match ? 'MATCH' : 'MISMATCH',
    };
  }

  async uploadDocuments(
    adoptionId: string,
    userId: string,
    userRole: UserRole,
    files: Express.Multer.File[],
  ) {
    if (!files || files.length === 0) {
      throw new BadRequestException('At least one document is required');
    }

    const adoption = await this.prisma.adoption.findUnique({
      where: { id: adoptionId },
    });

    if (!adoption) {
      throw new NotFoundException('Adoption not found');
    }

    const isParticipant =
      adoption.adopterId === userId ||
      adoption.ownerId === userId ||
      userRole === 'ADMIN';

    if (!isParticipant) {
      throw new ForbiddenException(
        'You are not allowed to upload documents for this adoption',
      );
    }

    const uploadedResults: {
      fileName: string;
      fileUrl: string;
      publicId: string;
      mimeType: string;
      size: number;
      sha256: string;
    }[] = [];

    for (const file of files) {
      const hashStream = crypto.createHash('sha256');
      hashStream.update(file.buffer);
      const sha256 = hashStream.digest('hex');

      const result = await this.cloudinary.uploadDocument(
        file.buffer,
        `adoptions/${adoptionId}`,
      );

      uploadedResults.push({
        fileName: file.originalname,
        fileUrl: result.secure_url,
        publicId: result.public_id,
        mimeType: file.mimetype,
        size: file.size,
        sha256,
      });
    }

    const createdDocuments: any[] = [];
    await this.prisma.$transaction(async (tx) => {
      for (const doc of uploadedResults) {
        const created = await tx.document.create({
          data: {
            ...doc,
            uploadedById: userId,
            adoptionId,
          },
        });
        createdDocuments.push(created);
      }
    });

    for (const doc of createdDocuments) {
      await this.eventsService.logEvent({
        entityType: EventEntityType.DOCUMENT,
        entityId: doc.id,
        eventType: EventType.DOCUMENT_UPLOADED,
        actorId: userId,
        payload: {
          documentId: doc.id,
          fileName: doc.fileName,
          sha256: doc.sha256,
          adoptionId,
        },
      });
    }

    return {
      message: 'Documents uploaded successfully',
      documents: createdDocuments,
    };
  }
}
