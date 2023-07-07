import { InputType, Field } from '@nestjs/graphql';

@InputType()
export class SearchDto {
  @Field(() => String, { defaultValue: '' })
  keyword: string;
}
