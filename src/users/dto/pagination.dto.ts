import { InputType, Int, Field } from '@nestjs/graphql';
import { IsOptional } from 'class-validator';

@InputType()
export class PaginationDto {
  @IsOptional()
  @Field(() => Int, { defaultValue: 1 })
  page: number;

  @IsOptional()
  @Field(() => Int, { defaultValue: 1 })
  limit: number;
}
